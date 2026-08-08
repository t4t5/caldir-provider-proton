use std::fmt;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::constants::{APP_VERSION, PROTON_API_URL, USER_AGENT};
use crate::hv::Challenge;
use crate::session::{Session, SessionStore};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthTokens {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct ApiClient {
    http: reqwest::Client,
    session: RwLock<Session>,
    store: Option<SessionStore>,
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug)]
struct ProtonApiError {
    code: i64,
    status: StatusCode,
    message: String,
    challenge: Option<Challenge>,
}

impl fmt::Display for ProtonApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(challenge) = &self.challenge {
            let methods = if challenge.methods.is_empty() {
                "unknown".to_string()
            } else {
                challenge.methods.join(", ")
            };
            return write!(
                formatter,
                "Proton requires human verification (methods: {methods}). Sign in at https://account.proton.me, then run `caldir connect proton` again"
            );
        }
        write!(
            formatter,
            "Proton API error {} (HTTP {}): {}",
            self.code, self.status, self.message
        )
    }
}

impl std::error::Error for ProtonApiError {}

pub(crate) fn is_time_window_too_big(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ProtonApiError>()
        .is_some_and(|error| error.code == 2000 && error.message == "Time window is too big")
}

pub(crate) fn human_verification_challenge(error: &anyhow::Error) -> Option<&Challenge> {
    error
        .downcast_ref::<ProtonApiError>()
        .and_then(|error| error.challenge.as_ref())
}

impl ApiClient {
    pub fn new(session: Session, store: SessionStore) -> Result<Self> {
        Ok(Self {
            http: build_http_client()?,
            session: RwLock::new(session),
            store: Some(store),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn transient(session: Session) -> Result<Self> {
        Ok(Self {
            http: build_http_client()?,
            session: RwLock::new(session),
            store: None,
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn session(&self) -> Session {
        self.session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        self.request(Method::GET, path, query, None, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        self.request(Method::POST, path, &[], Some(body), None)
            .await
    }

    pub async fn post_with_human_verification<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> Result<T> {
        self.request(Method::POST, path, &[], Some(body), Some(token))
            .await
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        self.request(Method::PUT, path, &[], Some(body), None).await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        human_verification_token: Option<&str>,
    ) -> Result<T> {
        let mut refreshed = false;
        let mut rate_limited = false;
        loop {
            let session = self.session();
            let response = self
                .send_once(
                    &session,
                    method.clone(),
                    path,
                    query,
                    body.clone(),
                    human_verification_token,
                )
                .await?;

            if response.status() == StatusCode::UNAUTHORIZED && !refreshed {
                self.refresh_if_current(&session.access_token).await?;
                refreshed = true;
                continue;
            }

            if response.status() == StatusCode::TOO_MANY_REQUESTS && !rate_limited {
                let delay = retry_after(&response).min(Duration::from_secs(30));
                tokio::time::sleep(delay).await;
                rate_limited = true;
                continue;
            }

            let status = response.status();
            let bytes = response
                .bytes()
                .await
                .context("Failed to read Proton response")?;
            if human_verification_token.is_some()
                && path == "/core/v4/auth"
                && std::env::var_os("CALDIR_PROTON_HV_DEBUG").is_some()
            {
                eprintln!(
                    "Proton human-verification retry response (HTTP {status}): {}",
                    String::from_utf8_lossy(&bytes)
                );
            }
            let value: Value = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "Proton returned invalid JSON (HTTP {status}): {}",
                    String::from_utf8_lossy(&bytes)
                )
            })?;
            check_api_response(status, &value)?;
            return serde_json::from_value(value).context("Failed to decode Proton response");
        }
    }

    async fn send_once(
        &self,
        session: &Session,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        human_verification_token: Option<&str>,
    ) -> Result<reqwest::Response> {
        let url = format!("{PROTON_API_URL}{path}");
        let mut request = self
            .http
            .request(method, url)
            .header("x-pm-appversion", APP_VERSION)
            .header("User-Agent", USER_AGENT)
            .header("x-pm-uid", &session.uid)
            .bearer_auth(&session.access_token)
            .query(query);
        request = attach_human_verification_headers(request, human_verification_token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.context("Proton API request failed")
    }

    async fn refresh_if_current(&self, failed_access_token: &str) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        if self.session().access_token != failed_access_token {
            return Ok(());
        }
        self.refresh().await
    }

    async fn refresh(&self) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct RefreshResponse {
            #[serde(rename = "UID")]
            uid: String,
            access_token: String,
            refresh_token: String,
        }

        let session = self.session();
        let response = self
            .http
            .post(format!("{PROTON_API_URL}/auth/v4/refresh"))
            .header("x-pm-appversion", APP_VERSION)
            .header("User-Agent", USER_AGENT)
            .header("x-pm-uid", &session.uid)
            .bearer_auth(&session.access_token)
            .json(&json!({
                "UID": session.uid,
                "RefreshToken": session.refresh_token,
                "ResponseType": "token",
                "GrantType": "refresh_token",
                "RedirectURI": "https://protonmail.ch"
            }))
            .send()
            .await
            .context("Failed to refresh Proton session")?;
        let status = response.status();
        let value: Value = response.json().await.context("Invalid refresh response")?;
        check_api_response(status, &value)
            .context("Proton session expired; run `caldir connect proton` to authenticate again")?;
        let refreshed: RefreshResponse =
            serde_json::from_value(value).context("Invalid refresh token response")?;
        let updated = {
            let mut session = self
                .session
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            session.uid = refreshed.uid;
            session.access_token = refreshed.access_token;
            session.refresh_token = refreshed.refresh_token;
            session.clone()
        };
        if let Some(store) = &self.store {
            store
                .save(&updated)
                .context("Failed to persist rotated Proton tokens")?;
        }
        Ok(())
    }
}

fn attach_human_verification_headers(
    request: reqwest::RequestBuilder,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    match token {
        Some(token) => request
            .header("x-pm-human-verification-token", token)
            .header("x-pm-human-verification-token-type", "captcha"),
        None => request,
    }
}

pub async fn create_unauth_session() -> Result<AuthTokens> {
    let response = build_http_client()?
        .post(format!("{PROTON_API_URL}/auth/v4/sessions"))
        .header("x-pm-appversion", APP_VERSION)
        .header("User-Agent", USER_AGENT)
        .header("x-enforce-unauthsession", "true")
        .json(&json!({}))
        .send()
        .await
        .context("Failed to create Proton unauthenticated session")?;
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .context("Invalid Proton session response")?;
    check_api_response(status, &value)?;
    serde_json::from_value(value).context("Invalid Proton session tokens")
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(14))
        .build()
        .context("Failed to initialize Proton HTTP client")
}

fn retry_after(response: &reqwest::Response) -> Duration {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(1))
}

fn check_api_response(status: StatusCode, value: &Value) -> Result<()> {
    let code = value.get("Code").and_then(Value::as_i64).unwrap_or(0);
    if status.is_success() && matches!(code, 0 | 1000 | 1001) {
        return Ok(());
    }

    let message = value
        .get("Error")
        .and_then(Value::as_str)
        .unwrap_or("unknown Proton API error");
    let challenge = (code == 9001).then(|| {
        let methods = value
            .pointer("/Details/HumanVerificationMethods")
            .or_else(|| value.pointer("/Details/Methods"))
            .and_then(Value::as_array)
            .map(|methods| {
                methods
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Challenge {
            token: value
                .pointer("/Details/HumanVerificationToken")
                .or_else(|| value.pointer("/Details/Token"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            methods,
            web_url: value
                .pointer("/Details/WebUrl")
                .and_then(Value::as_str)
                .unwrap_or("https://account.proton.me")
                .to_string(),
        }
    });
    if code == 8002 {
        bail!("Proton rejected the username or password");
    }
    if code == 10013 {
        bail!("Proton session expired; run `caldir connect proton` again");
    }
    Err(ProtonApiError {
        code,
        status,
        message: message.to_string(),
        challenge,
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_verification_is_actionable() {
        let error = check_api_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "Code": 9001,
                "Error": "Human verification required",
                "Details": {
                    "HumanVerificationMethods": ["captcha"],
                    "HumanVerificationToken": "challenge-token",
                    "WebUrl": "https://verify.example"
                }
            }),
        )
        .unwrap_err();
        let challenge = human_verification_challenge(&error).unwrap();
        assert_eq!(challenge.methods, ["captcha"]);
        assert_eq!(challenge.token, "challenge-token");
        assert_eq!(challenge.web_url, "https://verify.example");
        assert!(error.to_string().contains("https://account.proton.me"));
    }

    #[test]
    fn identifies_time_window_limit_errors() {
        let error = check_api_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "Code": 2000,
                "Error": "Time window is too big"
            }),
        )
        .unwrap_err();
        let error = error.context("Failed event page");

        assert!(is_time_window_too_big(&error));
    }

    #[test]
    fn does_not_misclassify_other_invalid_requests() {
        let error = check_api_response(
            StatusCode::BAD_REQUEST,
            &json!({
                "Code": 2000,
                "Error": "Invalid event type"
            }),
        )
        .unwrap_err();

        assert!(!is_time_window_too_big(&error));
    }

    #[test]
    fn attaches_human_verification_headers_only_when_solved() {
        let client = reqwest::Client::new();
        let request = attach_human_verification_headers(
            client.get("https://example.test"),
            Some("solved-token"),
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers()["x-pm-human-verification-token"],
            "solved-token"
        );
        assert_eq!(
            request.headers()["x-pm-human-verification-token-type"],
            "captcha"
        );

        let request = attach_human_verification_headers(client.get("https://example.test"), None)
            .build()
            .unwrap();
        assert!(
            !request
                .headers()
                .contains_key("x-pm-human-verification-token")
        );
        assert!(
            !request
                .headers()
                .contains_key("x-pm-human-verification-token-type")
        );
    }
}

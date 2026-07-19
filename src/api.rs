use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::constants::{APP_VERSION, USER_AGENT};
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
    session: Session,
    store: Option<SessionStore>,
}

impl ApiClient {
    pub fn new(session: Session, store: SessionStore) -> Result<Self> {
        Ok(Self {
            http: build_http_client()?,
            session,
            store: Some(store),
        })
    }

    pub fn transient(session: Session) -> Result<Self> {
        Ok(Self {
            http: build_http_client()?,
            session,
            store: None,
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub async fn get<T: DeserializeOwned>(
        &mut self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        self.request(Method::GET, path, query, None).await
    }

    pub async fn post<T: DeserializeOwned>(&mut self, path: &str, body: Value) -> Result<T> {
        self.request(Method::POST, path, &[], Some(body)).await
    }

    pub async fn put<T: DeserializeOwned>(&mut self, path: &str, body: Value) -> Result<T> {
        self.request(Method::PUT, path, &[], Some(body)).await
    }

    async fn request<T: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<T> {
        let mut refreshed = false;
        let mut rate_limited = false;
        loop {
            let response = self
                .send_once(method.clone(), path, query, body.clone())
                .await?;

            if response.status() == StatusCode::UNAUTHORIZED && !refreshed {
                self.refresh().await?;
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
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.session.base_url.trim_end_matches('/'), path);
        let mut request = self
            .http
            .request(method, url)
            .header("x-pm-appversion", APP_VERSION)
            .header("User-Agent", USER_AGENT)
            .header("x-pm-uid", &self.session.uid)
            .bearer_auth(&self.session.access_token)
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.context("Proton API request failed")
    }

    async fn refresh(&mut self) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct RefreshResponse {
            #[serde(rename = "UID")]
            uid: String,
            access_token: String,
            refresh_token: String,
        }

        let url = format!(
            "{}/auth/v4/refresh",
            self.session.base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .header("x-pm-appversion", APP_VERSION)
            .header("User-Agent", USER_AGENT)
            .header("x-pm-uid", &self.session.uid)
            .bearer_auth(&self.session.access_token)
            .json(&json!({
                "UID": self.session.uid,
                "RefreshToken": self.session.refresh_token,
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
        self.session.uid = refreshed.uid;
        self.session.access_token = refreshed.access_token;
        self.session.refresh_token = refreshed.refresh_token;
        if let Some(store) = &self.store {
            store
                .save(&self.session)
                .context("Failed to persist rotated Proton tokens")?;
        }
        Ok(())
    }
}

pub async fn create_unauth_session(base_url: &str) -> Result<AuthTokens> {
    let url = format!("{}/auth/v4/sessions", base_url.trim_end_matches('/'));
    let response = build_http_client()?
        .post(url)
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
    if code == 9001 {
        let methods = value
            .pointer("/Details/HumanVerificationMethods")
            .or_else(|| value.pointer("/Details/Methods"))
            .map(Value::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let web_url = value
            .pointer("/Details/WebUrl")
            .and_then(Value::as_str)
            .unwrap_or("https://account.proton.me");
        bail!(
            "Proton requires human verification (methods: {methods}). Complete it at {web_url}, then retry from the same network"
        );
    }
    if code == 8002 {
        bail!("Proton rejected the username or password");
    }
    if code == 10013 {
        bail!("Proton session expired; run `caldir connect proton` again");
    }
    bail!("Proton API error {code} (HTTP {status}): {message}");
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
                    "WebUrl": "https://verify.example"
                }
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("captcha"));
        assert!(message.contains("https://verify.example"));
    }
}

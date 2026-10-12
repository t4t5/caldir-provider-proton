use anyhow::{Context, Result, bail};
use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};
use serde::Deserialize;
use serde_json::json;

use crate::api::{ApiClient, human_verification_challenge};
use crate::hv;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AuthInfo {
    version: u8,
    modulus: String,
    server_ephemeral: String,
    salt: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoginResponse {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub server_proof: String,
    #[serde(default = "default_password_mode")]
    pub password_mode: u8,
    #[serde(rename = "2FA", default)]
    pub two_factor: TwoFactor,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactor {
    #[serde(default)]
    pub enabled: u32,
}

pub async fn login_srp(
    client: &mut ApiClient,
    username: &str,
    password: &str,
) -> Result<LoginResponse> {
    match login_srp_attempt(client, username, password, None).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let Some(challenge) = human_verification_challenge(&error) else {
                return Err(error);
            };
            let token = hv::resolve(challenge)?;
            login_srp_attempt(client, username, password, Some(&token))
                .await
                .context("Proton login failed after human verification")
        }
    }
}

async fn login_srp_attempt(
    client: &mut ApiClient,
    username: &str,
    password: &str,
    human_verification_token: Option<&str>,
) -> Result<LoginResponse> {
    let info_body = json!({ "Username": username });
    let info: AuthInfo = match human_verification_token {
        Some(token) => {
            client
                .post_with_human_verification("/core/v4/auth/info", info_body, token)
                .await
        }
        None => client.post("/core/v4/auth/info", info_body).await,
    }
    .context("Failed to load Proton SRP parameters")?;
    let version =
        SrpHashVersion::try_from(info.version).context("Unsupported Proton SRP version")?;
    let auth = SRPAuth::with_pgp(
        Some(username),
        password,
        version,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )
    .context("Failed to initialize Proton SRP")?;
    let proof: SRPProofB64 = auth
        .generate_proofs()
        .context("Failed to generate Proton SRP proof")?
        .into();
    let auth_body = json!({
        "Username": username,
        "ClientProof": proof.client_proof,
        "ClientEphemeral": proof.client_ephemeral,
        "SRPSession": info.srp_session,
    });
    let response: LoginResponse = match human_verification_token {
        Some(token) => {
            client
                .post_with_human_verification("/core/v4/auth", auth_body, token)
                .await
        }
        None => client.post("/core/v4/auth", auth_body).await,
    }
    .context("Proton login failed")?;
    if !proof.compare_server_proof(&response.server_proof) {
        bail!("Proton SRP server proof verification failed");
    }
    Ok(response)
}

pub async fn submit_totp(client: &mut ApiClient, code: &str) -> Result<()> {
    let _: serde_json::Value = client
        .post("/core/v4/auth/2fa", json!({ "TwoFactorCode": code }))
        .await
        .context("Proton rejected the TOTP code")?;
    Ok(())
}

fn default_password_mode() -> u8 {
    1
}

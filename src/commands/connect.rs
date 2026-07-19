use anyhow::{Context, Result, bail};
use base64::Engine as _;
use caldir_core::provider::ProviderStorage;
use caldir_core::rpc::{
    Connect, ConnectResponse, ConnectStepKind, CredentialField, CredentialsData, FieldType,
};

use crate::api::{ApiClient, create_unauth_session};
use crate::auth::{login_srp, submit_totp};
use crate::constants::{DEFAULT_BASE_URL, PROVIDER_NAME};
use crate::keys::{derive_key_password, unlock_account};
use crate::session::{PendingSession, Session, SessionStore};

pub async fn handle(cmd: Connect) -> Result<ConnectResponse> {
    let storage = ProviderStorage::for_provider(PROVIDER_NAME)?;
    let store = SessionStore::new(storage);
    if let Some(email) = submitted(&cmd, "email") {
        let password = required(&cmd, "password")?;
        let base_url =
            std::env::var("PROTON_API_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let unauth = create_unauth_session(&base_url).await?;
        let transient = Session {
            base_url: base_url.clone(),
            email: email.to_string(),
            uid: unauth.uid,
            access_token: unauth.access_token,
            refresh_token: unauth.refresh_token,
            key_password: String::new(),
            password_mode: 1,
        };
        let mut client = ApiClient::transient(transient)?;
        let login = login_srp(&mut client, email, password).await?;
        if login.two_factor.enabled != 0 && login.two_factor.enabled & 1 == 0 {
            bail!(
                "This Proton account requires FIDO2 authentication, which caldir-provider-proton does not support"
            );
        }
        let pending = PendingSession {
            base_url,
            email: email.to_string(),
            uid: login.uid,
            access_token: login.access_token,
            refresh_token: login.refresh_token,
            login_password: password.to_string(),
            password_mode: login.password_mode,
            needs_totp: login.two_factor.enabled & 1 != 0,
        };
        if pending.needs_totp {
            store.save_pending(&pending)?;
            return prompt("totp", "TOTP code", FieldType::Password, None);
        }
        if pending.password_mode == 2 {
            store.save_pending(&pending)?;
            return prompt(
                "mailbox_password",
                "Mailbox password",
                FieldType::Password,
                Some("This account uses a separate password to unlock encrypted data."),
            );
        }
        return finish_login(&store, pending.clone(), &pending.login_password).await;
    }

    if let Some(totp) = submitted(&cmd, "totp") {
        let mut pending = store.load_pending()?;
        if !pending.needs_totp {
            bail!("The pending Proton login is not waiting for a TOTP code");
        }
        let transient = session_from_pending(&pending, String::new());
        let mut client = ApiClient::transient(transient)?;
        submit_totp(&mut client, totp).await?;
        pending.needs_totp = false;
        pending.uid = client.session().uid.clone();
        pending.access_token = client.session().access_token.clone();
        pending.refresh_token = client.session().refresh_token.clone();
        if pending.password_mode == 2 {
            store.save_pending(&pending)?;
            return prompt(
                "mailbox_password",
                "Mailbox password",
                FieldType::Password,
                Some("This account uses a separate password to unlock encrypted data."),
            );
        }
        let password = pending.login_password.clone();
        return finish_login(&store, pending, &password).await;
    }

    if let Some(mailbox_password) = submitted(&cmd, "mailbox_password") {
        let pending = store.load_pending()?;
        if pending.needs_totp {
            bail!("Submit the Proton TOTP code before the mailbox password");
        }
        if pending.password_mode != 2 {
            bail!("The pending Proton login does not require a mailbox password");
        }
        return finish_login(&store, pending, mailbox_password).await;
    }

    Ok(ConnectResponse::NeedsInput {
        step: ConnectStepKind::Credentials,
        data: serde_json::to_value(CredentialsData {
            fields: vec![
                CredentialField {
                    id: "email".into(),
                    label: "Proton email".into(),
                    field_type: FieldType::Text,
                    required: true,
                    help: None,
                },
                CredentialField {
                    id: "password".into(),
                    label: "Password".into(),
                    field_type: FieldType::Password,
                    required: true,
                    help: None,
                },
            ],
        })?,
    })
}

async fn finish_login(
    store: &SessionStore,
    pending: PendingSession,
    mailbox_password: &str,
) -> Result<ConnectResponse> {
    let transient = session_from_pending(&pending, String::new());
    let mut client = ApiClient::transient(transient)?;
    let key_password = derive_key_password(&mut client, mailbox_password).await?;
    let session = Session {
        base_url: pending.base_url,
        email: pending.email,
        uid: client.session().uid.clone(),
        access_token: client.session().access_token.clone(),
        refresh_token: client.session().refresh_token.clone(),
        key_password: base64::engine::general_purpose::STANDARD.encode(key_password),
        password_mode: pending.password_mode,
    };
    let pgp = proton_crypto::new_pgp_provider();
    unlock_account(&mut client, &session, &pgp)
        .await
        .context("Proton login succeeded but encrypted account keys could not be unlocked")?;
    store.save(&session)?;
    store.clear_pending()?;
    Ok(ConnectResponse::Done {
        account_identifier: Some(session.account_identifier()),
        calendars: None,
    })
}

fn session_from_pending(pending: &PendingSession, key_password: String) -> Session {
    Session {
        base_url: pending.base_url.clone(),
        email: pending.email.clone(),
        uid: pending.uid.clone(),
        access_token: pending.access_token.clone(),
        refresh_token: pending.refresh_token.clone(),
        key_password,
        password_mode: pending.password_mode,
    }
}

fn prompt(
    id: &str,
    label: &str,
    field_type: FieldType,
    help: Option<&str>,
) -> Result<ConnectResponse> {
    Ok(ConnectResponse::NeedsInput {
        step: ConnectStepKind::Credentials,
        data: serde_json::to_value(CredentialsData {
            fields: vec![CredentialField {
                id: id.into(),
                label: label.into(),
                field_type,
                required: true,
                help: help.map(str::to_string),
            }],
        })?,
    })
}

fn submitted<'a>(cmd: &'a Connect, key: &str) -> Option<&'a str> {
    cmd.data
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
}

fn required<'a>(cmd: &'a Connect, key: &str) -> Result<&'a str> {
    submitted(cmd, key).with_context(|| format!("Missing required Proton credential: {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initial_step_requests_email_and_password() {
        let response = handle(Connect {
            options: serde_json::Map::new(),
            data: serde_json::Map::new(),
        })
        .await
        .unwrap();
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["status"], "needs_input");
        assert_eq!(value["fields"][0]["id"], "email");
        assert_eq!(value["fields"][1]["id"], "password");
    }
}

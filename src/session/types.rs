use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub base_url: String,
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub key_password: String,
    pub password_mode: u8,
}

impl Session {
    pub fn account_identifier(&self) -> String {
        self.email.clone()
    }

    pub(super) fn slug(email: &str) -> String {
        email
            .to_ascii_lowercase()
            .replace(['/', '\\', ':', '@', '.'], "_")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSession {
    pub base_url: String,
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub login_password: String,
    pub password_mode: u8,
    pub needs_totp: bool,
}

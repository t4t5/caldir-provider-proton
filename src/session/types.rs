use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
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
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Only kept when the key secret must be derived from it after the TOTP
    /// step; two-password accounts submit their mailbox password instead.
    #[serde(default)]
    pub login_password: Option<String>,
    pub password_mode: u8,
    pub needs_totp: bool,
    /// Unix seconds. Logins older than [`PENDING_TTL_SECONDS`] are discarded
    /// so an abandoned prompt doesn't leave the password on disk.
    #[serde(default)]
    pub created_at: i64,
}

pub const PENDING_TTL_SECONDS: i64 = 10 * 60;

impl PendingSession {
    pub fn is_expired(&self, now: i64) -> bool {
        !(0..PENDING_TTL_SECONDS).contains(&(now - self.created_at))
    }
}

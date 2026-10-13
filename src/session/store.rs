use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use caldir_core::provider::ProviderStorage;

use super::{PendingSession, Session};

#[derive(Clone)]
pub struct SessionStore {
    storage: ProviderStorage,
}

impl SessionStore {
    pub fn new(storage: ProviderStorage) -> Self {
        Self { storage }
    }

    pub fn save(&self, session: &Session) -> Result<()> {
        let path = self
            .session_dir()
            .join(format!("{}.toml", Session::slug(&session.email)));
        atomic_private_write(&path, &toml::to_string_pretty(session)?)
    }

    pub fn load(&self, account_identifier: &str) -> Result<Session> {
        let path = self
            .session_dir()
            .join(format!("{}.toml", Session::slug(account_identifier)));
        let contents = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Proton session for {account_identifier} not found - run `caldir connect proton`"
            )
        })?;
        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse Proton session {}", path.display()))
    }

    pub fn save_pending(&self, pending: &PendingSession) -> Result<()> {
        atomic_private_write(&self.pending_path(), &toml::to_string_pretty(pending)?)
    }

    pub fn load_pending(&self) -> Result<PendingSession> {
        self.discard_stale_pending()?;
        let path = self.pending_path();
        let contents = std::fs::read_to_string(&path).context(
            "No pending Proton login found (it may have expired); restart `caldir connect proton`",
        )?;
        toml::from_str(&contents).context("Failed to parse pending Proton login")
    }

    /// Deletes a pending login that has expired or can't be parsed.
    pub fn discard_stale_pending(&self) -> Result<()> {
        let Ok(contents) = std::fs::read_to_string(self.pending_path()) else {
            return Ok(());
        };
        let now = chrono::Utc::now().timestamp();
        let fresh = toml::from_str::<PendingSession>(&contents)
            .is_ok_and(|pending| !pending.is_expired(now));
        if !fresh {
            self.clear_pending()?;
        }
        Ok(())
    }

    pub fn clear_pending(&self) -> Result<()> {
        let path = self.pending_path();
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn session_dir(&self) -> PathBuf {
        self.storage.root().join("session")
    }

    fn pending_path(&self) -> PathBuf {
        self.storage.root().join("pending.toml")
    }
}

fn atomic_private_write(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().context("Session path has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create {}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    create_private_file(&temporary)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .with_context(|| format!("Failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("Failed to atomically replace {}", path.display()))?;
    Ok(())
}

/// Owner-only from creation, so secrets are never briefly readable by others.
fn create_private_file(path: &Path) -> std::io::Result<File> {
    // Clear a leftover from an interrupted write so `create_new` can succeed.
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::types::PENDING_TTL_SECONDS;
    use tempfile::TempDir;

    fn sample_session() -> Session {
        Session {
            email: "alice@proton.me".into(),
            uid: "uid".into(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            key_password: "c2VjcmV0".into(),
            password_mode: 1,
        }
    }

    fn sample_pending(created_at: i64) -> PendingSession {
        PendingSession {
            email: "alice@example.test".into(),
            uid: "uid".into(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            login_password: Some("password".into()),
            password_mode: 1,
            needs_totp: true,
            created_at,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn session_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        let session = sample_session();
        store.save(&session).unwrap();
        let loaded = store.load("alice@proton.me").unwrap();
        assert_eq!(loaded.access_token, "access");
        assert_eq!(loaded.key_password, "c2VjcmV0");
    }

    #[test]
    fn pending_round_trip_and_clear() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        store.save_pending(&sample_pending(now())).unwrap();
        assert!(store.load_pending().unwrap().needs_totp);
        store.clear_pending().unwrap();
        assert!(store.load_pending().is_err());
    }

    #[test]
    fn expired_pending_is_deleted_on_load() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        store
            .save_pending(&sample_pending(now() - PENDING_TTL_SECONDS))
            .unwrap();
        assert!(store.load_pending().is_err());
        assert!(!tmp.path().join("pending.toml").exists());
    }

    #[test]
    fn discard_stale_pending_keeps_fresh_login() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        store.save_pending(&sample_pending(now())).unwrap();
        store.discard_stale_pending().unwrap();
        assert!(tmp.path().join("pending.toml").exists());
    }

    #[test]
    fn discard_stale_pending_removes_legacy_login_without_timestamp() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        let path = tmp.path().join("pending.toml");
        std::fs::write(
            &path,
            r#"email = "alice@example.test"
uid = "uid"
access_token = "access"
refresh_token = "refresh"
login_password = "password"
password_mode = 1
needs_totp = true
"#,
        )
        .unwrap();
        store.discard_stale_pending().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn discard_stale_pending_without_file_is_ok() {
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        store.discard_stale_pending().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn session_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = SessionStore::new(ProviderStorage::new(tmp.path()));
        let session = sample_session();
        store.save(&session).unwrap();
        let path = tmp
            .path()
            .join("session")
            .join(format!("{}.toml", Session::slug(&session.email)));
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn leftover_temporary_file_does_not_leak_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("pending.toml");
        let leftover = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&leftover, "stale").unwrap();
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_private_write(&path, "secret").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

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
        let path = self.pending_path();
        let contents = std::fs::read_to_string(&path)
            .context("No pending Proton login found; restart `caldir connect proton`")?;
        toml::from_str(&contents).context("Failed to parse pending Proton login")
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
    std::fs::write(&temporary, contents)
        .with_context(|| format!("Failed to write {}", temporary.display()))?;
    set_private_permissions(&temporary)?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("Failed to atomically replace {}", path.display()))?;
    set_private_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let pending = PendingSession {
            email: "alice@example.test".into(),
            uid: "uid".into(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            login_password: "password".into(),
            password_mode: 1,
            needs_totp: true,
        };
        store.save_pending(&pending).unwrap();
        assert!(store.load_pending().unwrap().needs_totp);
        store.clear_pending().unwrap();
        assert!(store.load_pending().is_err());
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
}

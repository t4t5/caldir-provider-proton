use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::{Command, Output};

const HELPER_NAME: &str = "caldir-proton-hv";
const HELPER_ENV: &str = "CALDIR_PROTON_HV_HELPER";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub token: String,
    pub methods: Vec<String>,
    pub web_url: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HvError {
    Unavailable(String),
    Cancelled,
    Failed(String),
}

impl fmt::Display for HvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(detail) => {
                write!(
                    formatter,
                    "human-verification helper is unavailable: {detail}"
                )
            }
            Self::Cancelled => formatter.write_str("human verification was cancelled"),
            Self::Failed(detail) => write!(formatter, "human verification failed: {detail}"),
        }
    }
}

impl std::error::Error for HvError {}

pub fn resolve(challenge: &Challenge) -> Result<String, HvError> {
    if !challenge
        .methods
        .iter()
        .any(|method| method.eq_ignore_ascii_case("captcha"))
    {
        let methods = if challenge.methods.is_empty() {
            "unknown".to_string()
        } else {
            challenge.methods.join(", ")
        };
        return Err(HvError::Unavailable(format!(
            "the offered methods are not supported ({methods})"
        )));
    }
    if challenge.token.is_empty() {
        return Err(HvError::Failed(
            "Proton did not include a challenge token".to_string(),
        ));
    }

    let helper = locate_helper();
    resolve_with_helper(&helper, &challenge.token)
}

fn locate_helper() -> OsString {
    if let Some(helper) = env::var_os(HELPER_ENV).filter(|value| !value.is_empty()) {
        return helper;
    }

    if let Ok(executable) = env::current_exe()
        && let Some(directory) = executable.parent()
    {
        let sibling = directory.join(helper_filename());
        if sibling.is_file() {
            return sibling.into_os_string();
        }
    }

    OsString::from(HELPER_NAME)
}

fn helper_filename() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(format!("{HELPER_NAME}.exe"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(HELPER_NAME)
    }
}

fn resolve_with_helper(helper: &OsStr, token: &str) -> Result<String, HvError> {
    let output = Command::new(helper).arg(token).output().map_err(|error| {
        HvError::Unavailable(format!(
            "could not start {}: {error}",
            helper.to_string_lossy()
        ))
    })?;
    translate_output(output)
}

fn translate_output(output: Output) -> Result<String, HvError> {
    let detail = stderr_detail(&output.stderr);
    match output.status.code() {
        Some(0) => {
            let token = String::from_utf8(output.stdout)
                .map_err(|_| HvError::Failed("helper returned a non-UTF-8 token".to_string()))?;
            let token = token.trim();
            if token.is_empty() {
                Err(HvError::Failed(
                    "helper returned an empty token".to_string(),
                ))
            } else {
                Ok(token.to_string())
            }
        }
        Some(3 | 126 | 127) => Err(HvError::Unavailable(detail)),
        Some(4) => Err(HvError::Cancelled),
        Some(code) => Err(HvError::Failed(if detail.is_empty() {
            format!("helper exited with status {code}")
        } else {
            detail
        })),
        None => Err(HvError::Failed(if detail.is_empty() {
            "helper terminated without an exit status".to_string()
        } else {
            detail
        })),
    }
}

fn stderr_detail(stderr: &[u8]) -> String {
    let line = String::from_utf8_lossy(stderr)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    line.strip_prefix("hv: ")
        .and_then(|line| line.split_once(": ").map(|(_, detail)| detail))
        .unwrap_or(&line)
        .to_string()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static HELPER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn helper(exit_code: i32, stdout: &str, stderr: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        let script = format!(
            "#!/bin/sh\nprintf '%s' '{}'\nprintf '%s' '{}' >&2\nexit {}\n",
            stdout, stderr, exit_code
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        (directory, path)
    }

    fn run_helper(exit_code: i32, stdout: &str, stderr: &str) -> Result<String, HvError> {
        let _guard = HELPER_TEST_LOCK.lock().unwrap();
        let (_directory, helper) = helper(exit_code, stdout, stderr);
        resolve_with_helper(helper.as_os_str(), "challenge")
    }

    #[test]
    fn returns_token_on_success() {
        assert_eq!(run_helper(0, "solved-token\n", "").unwrap(), "solved-token");
    }

    #[test]
    fn maps_usage_to_failed() {
        assert_eq!(
            run_helper(2, "", "hv: usage: expected one token\n").unwrap_err(),
            HvError::Failed("expected one token".to_string())
        );
    }

    #[test]
    fn maps_webview_unavailable() {
        assert_eq!(
            run_helper(3, "", "hv: unavailable: no display\n").unwrap_err(),
            HvError::Unavailable("no display".to_string())
        );
    }

    #[test]
    fn maps_cancelled() {
        assert_eq!(
            run_helper(4, "", "hv: cancelled: window closed\n").unwrap_err(),
            HvError::Cancelled
        );
    }

    #[test]
    fn maps_network_failure() {
        assert_eq!(
            run_helper(5, "", "hv: network: timed out\n").unwrap_err(),
            HvError::Failed("timed out".to_string())
        );
    }

    #[test]
    fn maps_dynamic_loader_status_126_to_unavailable() {
        assert_eq!(
            run_helper(126, "", "missing libwebkit2gtk\n").unwrap_err(),
            HvError::Unavailable("missing libwebkit2gtk".to_string())
        );
    }

    #[test]
    fn maps_dynamic_loader_status_127_to_unavailable() {
        assert_eq!(
            run_helper(127, "", "missing libwebkit2gtk\n").unwrap_err(),
            HvError::Unavailable("missing libwebkit2gtk".to_string())
        );
    }

    #[test]
    fn rejects_empty_success_output() {
        assert_eq!(
            run_helper(0, "", "").unwrap_err(),
            HvError::Failed("helper returned an empty token".to_string())
        );
    }
}

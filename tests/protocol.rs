use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn initial_connect_is_one_clean_json_response() {
    let storage = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_caldir-provider-proton"))
        .env("CALDIR_PROVIDER_STORAGE_DIR", storage.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        json!({
            "command": "connect",
            "params": { "options": {}, "data": {} }
        })
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not one JSON response: {error}: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(response["status"], "success");
    assert_eq!(response["data"]["status"], "needs_input");
    assert_eq!(response["data"]["step"], "credentials");
}

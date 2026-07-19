use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use tempfile::TempDir;

#[test]
fn provider_crud_against_dedicated_account() -> Result<()> {
    let Ok(email) = std::env::var("PROTON_TEST_EMAIL") else {
        eprintln!("skipping integration test: PROTON_TEST_EMAIL is not set");
        return Ok(());
    };
    let password =
        std::env::var("PROTON_TEST_PASSWORD").context("PROTON_TEST_PASSWORD must be set")?;
    let storage = TempDir::new()?;

    let mut connect = rpc(
        storage.path(),
        json!({
            "command": "connect",
            "params": {
                "options": {},
                "data": { "email": email, "password": password }
            }
        }),
    )?;
    while connect_data(&connect)?["status"] == "needs_input" {
        let fields = connect_data(&connect)?["fields"]
            .as_array()
            .context("connect prompt has no fields")?;
        let id = fields
            .first()
            .and_then(|field| field["id"].as_str())
            .context("connect prompt has no field id")?;
        let value = match id {
            "totp" => current_totp(
                &std::env::var("PROTON_TEST_TOTP_SECRET")
                    .context("PROTON_TEST_TOTP_SECRET must be set for a 2FA account")?,
            )?,
            "mailbox_password" => std::env::var("PROTON_TEST_MAILBOX_PASSWORD")
                .context("PROTON_TEST_MAILBOX_PASSWORD must be set for a two-password account")?,
            other => bail!("unexpected Proton connect prompt: {other}"),
        };
        let mut data = serde_json::Map::new();
        data.insert(id.to_string(), Value::String(value));
        connect = rpc(
            storage.path(),
            json!({
                "command": "connect",
                "params": { "options": {}, "data": data }
            }),
        )?;
    }
    let account = connect_data(&connect)?["account_identifier"]
        .as_str()
        .context("connect response has no account_identifier")?
        .to_string();
    let calendars = rpc(
        storage.path(),
        json!({
            "command": "list_calendars",
            "params": { "account_identifier": account }
        }),
    )?;
    let calendar = success_data(&calendars)?
        .as_array()
        .and_then(|calendars| {
            calendars
                .iter()
                .find(|calendar| calendar["read_only"] != true)
        })
        .context("test account has no writable calendar")?;
    let calendar_id = calendar["remote"]["proton_calendar"]
        .as_str()
        .context("calendar has no proton_calendar")?
        .to_string();
    let remote = json!({
        "proton_account": account,
        "proton_calendar": calendar_id,
    });
    let uid = format!(
        "caldir-proton-integration-{}@example.invalid",
        std::process::id()
    );
    let initial = event_ics(&uid, "Created");
    let created = event_rpc(storage.path(), "create_event", &remote, &initial)?;
    assert!(created.contains("X-PROTON-ITEM:"));

    let listed = list_events(storage.path(), &remote)?;
    let listed_event = listed
        .iter()
        .find(|event| event.contains(&uid))
        .context("created event was not listed")?;
    assert!(listed_event.contains("TRIGGER;RELATED=START:-PT10M"));

    let updated = event_rpc(
        storage.path(),
        "update_event",
        &remote,
        &created.replace("SUMMARY:Created", "SUMMARY:Updated"),
    )?;
    assert!(updated.contains("SUMMARY:Updated"));
    let listed = list_events(storage.path(), &remote)?;
    assert!(
        listed
            .iter()
            .any(|event| event.contains(&uid) && event.contains("SUMMARY:Updated"))
    );

    event_rpc(storage.path(), "delete_event", &remote, &updated)?;
    assert!(
        !list_events(storage.path(), &remote)?
            .iter()
            .any(|event| event.contains(&uid))
    );
    Ok(())
}

fn event_ics(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:CALDIR\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:20260720T100000Z\r\nDTEND:20260720T110000Z\r\nSUMMARY:{summary}\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER;RELATED=START:-PT10M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

fn list_events(storage: &std::path::Path, remote: &Value) -> Result<Vec<String>> {
    let response = rpc(
        storage,
        json!({
            "command": "list_events",
            "params": {
                "proton_account": remote["proton_account"],
                "proton_calendar": remote["proton_calendar"],
                "from": "2026-07-19T00:00:00+00:00",
                "to": "2026-07-22T00:00:00+00:00"
            }
        }),
    )?;
    success_data(&response)?
        .as_array()
        .context("list_events response is not an array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .context("list_events entry is not ICS")
        })
        .collect()
}

fn event_rpc(
    storage: &std::path::Path,
    command: &str,
    remote: &Value,
    event: &str,
) -> Result<String> {
    let response = rpc(
        storage,
        json!({
            "command": command,
            "params": {
                "proton_account": remote["proton_account"],
                "proton_calendar": remote["proton_calendar"],
                "event": event
            }
        }),
    )?;
    if command == "delete_event" {
        success_data(&response)?;
        return Ok(String::new());
    }
    success_data(&response)?
        .as_str()
        .map(str::to_string)
        .context("event response is not ICS")
}

fn rpc(storage: &std::path::Path, request: Value) -> Result<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_caldir-provider-proton"))
        .env("CALDIR_PROVIDER_STORAGE_DIR", storage)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn provider")?;
    writeln!(
        child.stdin.as_mut().context("Provider stdin unavailable")?,
        "{request}"
    )?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "provider exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "Provider returned invalid JSON: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn success_data(response: &Value) -> Result<&Value> {
    if response["status"] != "success" {
        bail!("provider returned error: {response}");
    }
    Ok(&response["data"])
}

fn connect_data(response: &Value) -> Result<&Value> {
    success_data(response)
}

fn current_totp(secret: &str) -> Result<String> {
    let key = decode_base32(secret)?;
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).context("invalid TOTP secret")?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0_u64;
    let mut bits = 0_u8;
    for byte in value.bytes().filter(|byte| !matches!(byte, b' ' | b'-')) {
        if byte == b'=' {
            break;
        }
        let upper = byte.to_ascii_uppercase();
        let digit = match upper {
            b'A'..=b'Z' => upper - b'A',
            b'2'..=b'7' => upper - b'2' + 26,
            _ => bail!("invalid base32 character in PROTON_TEST_TOTP_SECRET"),
        };
        buffer = (buffer << 5) | u64::from(digit);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u64 << bits).saturating_sub(1);
        }
    }
    if output.is_empty() {
        bail!("PROTON_TEST_TOTP_SECRET is empty");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base32() {
        assert_eq!(decode_base32("MZXW6===").unwrap(), b"foo");
    }
}

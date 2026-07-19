use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use caldir_core::Event;
use proton_crypto::crypto::{
    DataEncoding, Decryptor, DecryptorSync, DetachedSignatureVariant, Encryptor, EncryptorSync,
    PGPMessage, PGPProviderSync, SessionKeyAlgorithm, Signer, SignerSync, VerifiedData, Verifier,
    VerifierSync,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::ApiClient;
use crate::constants::PAGE_SIZE;
use crate::keys::UnlockedAccount;
use crate::mapping::{cards_from_event, event_from_payloads, notifications_from_event};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarRecord {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Type", default)]
    pub kind: u32,
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub members: Vec<CalendarMember>,
}

impl CalendarRecord {
    pub fn display_name(&self) -> Option<&str> {
        self.members
            .first()
            .map(|member| member.name.as_str())
            .filter(|name| !name.is_empty())
            .or((!self.name.is_empty()).then_some(self.name.as_str()))
    }

    pub fn display_color(&self) -> Option<&str> {
        self.members
            .first()
            .map(|member| member.color.as_str())
            .filter(|color| !color.is_empty())
            .or((!self.color.is_empty()).then_some(self.color.as_str()))
    }

    pub fn read_only(&self) -> bool {
        self.kind != 0
            || self.flags & 16 != 0
            || self
                .members
                .first()
                .and_then(|member| member.permissions)
                .is_some_and(|permissions| permissions & 16 == 0)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarMember {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub permissions: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarsResponse {
    calendars: Vec<CalendarRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarBootstrap {
    keys: Vec<CalendarKey>,
    passphrase: CalendarPassphrase,
    members: Vec<CalendarMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarKey {
    private_key: String,
    #[serde(default)]
    flags: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarPassphrase {
    member_passphrases: Vec<MemberPassphrase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MemberPassphrase {
    #[serde(rename = "MemberID")]
    member_id: String,
    passphrase: String,
    signature: String,
}

pub struct CalendarKeys<P: PGPProviderSync> {
    pub member_id: String,
    pub calendar_private: P::PrivateKey,
    pub calendar_public: P::PublicKey,
    pub address_private: P::PrivateKey,
    pub address_public: P::PublicKey,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawEvent {
    #[serde(rename = "ID")]
    pub id: String,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(default)]
    pub start_timezone: Option<String>,
    #[serde(default)]
    pub end_timezone: Option<String>,
    #[serde(default)]
    pub full_day: u8,
    #[serde(rename = "UID", default)]
    pub uid: String,
    #[serde(rename = "RRule", default)]
    pub rrule: Option<String>,
    #[serde(rename = "RecurrenceID", default)]
    pub recurrence_id: Option<i64>,
    #[serde(default)]
    pub exdates: Vec<i64>,
    #[serde(default)]
    pub modify_time: Option<i64>,
    #[serde(default)]
    pub sequence: Option<i64>,
    #[serde(default)]
    pub permissions: Option<u32>,
    #[serde(default)]
    pub is_organizer: Option<u8>,
    #[serde(default)]
    pub shared_key_packet: Option<String>,
    #[serde(default)]
    pub address_key_packet: Option<String>,
    #[serde(default)]
    pub calendar_key_packet: Option<String>,
    #[serde(default)]
    pub shared_events: Vec<EventPayload>,
    #[serde(default)]
    pub calendar_events: Vec<EventPayload>,
    #[serde(default)]
    pub attendees_events: Vec<EventPayload>,
    #[serde(default)]
    pub attendees_info: AttendeesInfo,
    #[serde(default)]
    pub notifications: Option<Vec<Notification>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventPayload {
    #[serde(rename = "Type")]
    pub kind: u8,
    pub data: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub author: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Notification {
    #[serde(rename = "Type")]
    pub kind: u8,
    pub trigger: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttendeesInfo {
    #[serde(default)]
    pub attendees: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EventsResponse {
    #[serde(default)]
    events: Vec<RawEvent>,
    #[serde(default)]
    more: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EventResponse {
    event: RawEvent,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Card {
    #[serde(rename = "Type")]
    kind: u8,
    data: String,
    signature: String,
}

pub async fn list_calendars(client: &mut ApiClient) -> Result<Vec<CalendarRecord>> {
    let response: CalendarsResponse = client.get("/calendar/v1", &[]).await?;
    Ok(response.calendars)
}

pub async fn unlock_calendar<P: PGPProviderSync>(
    client: &mut ApiClient,
    account: &UnlockedAccount<P>,
    pgp: &P,
    calendar_id: &str,
) -> Result<CalendarKeys<P>> {
    let path = format!("/calendar/v2/{calendar_id}/bootstrap");
    let bootstrap: CalendarBootstrap = client
        .get(&path, &[])
        .await
        .with_context(|| format!("Failed to bootstrap Proton calendar {calendar_id}"))?;
    let (member, address) = bootstrap
        .members
        .iter()
        .find_map(|member| {
            account
                .address(&member.address_id)
                .map(|address| (member, address))
        })
        .context("No unlocked Proton address matches the calendar member")?;
    let address_key = address
        .keys
        .primary_default()
        .context("Calendar member address has no primary key")?;
    let member_passphrase = bootstrap
        .passphrase
        .member_passphrases
        .iter()
        .find(|passphrase| passphrase.member_id == member.id)
        .context("Calendar bootstrap has no passphrase for the current member")?;
    let passphrase = pgp
        .new_decryptor()
        .with_decryption_key_refs(&address.keys)
        .with_verification_key_refs(&address.keys)
        .with_detached_signature_ref(
            member_passphrase.signature.as_bytes(),
            DetachedSignatureVariant::Plaintext,
            true,
        )
        .decrypt(&member_passphrase.passphrase, DataEncoding::Armor)
        .context("Failed to decrypt Proton calendar passphrase")?;
    passphrase
        .verification_result()
        .context("Proton calendar passphrase signature verification failed")?;
    let calendar_key = bootstrap
        .keys
        .iter()
        .find(|key| key.flags & 2 != 0)
        .or_else(|| bootstrap.keys.first())
        .context("Calendar bootstrap has no key")?;
    let calendar_private = pgp
        .private_key_import(
            &calendar_key.private_key,
            passphrase.as_bytes(),
            DataEncoding::Armor,
        )
        .context("Failed to unlock Proton calendar key")?;
    let calendar_public = pgp
        .private_key_to_public_key(&calendar_private)
        .context("Failed to derive Proton calendar public key")?;
    Ok(CalendarKeys {
        member_id: member.id.clone(),
        calendar_private,
        calendar_public,
        address_private: address_key.private_key.clone(),
        address_public: address_key.public_key.clone(),
    })
}

pub async fn list_events<P: PGPProviderSync>(
    client: &mut ApiClient,
    account: &UnlockedAccount<P>,
    pgp: &P,
    calendar_id: &str,
    from: i64,
    to: i64,
) -> Result<Vec<Event>> {
    let keys = unlock_calendar(client, account, pgp, calendar_id).await?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for query_type in 0..=3 {
        let mut windows = vec![(from, to)];
        while let Some((window_from, window_to)) = windows.pop() {
            let mut page = 0_usize;
            loop {
                let path = format!("/calendar/v1/{calendar_id}/events");
                let response: EventsResponse = match client
                    .get(
                        &path,
                        &[
                            ("Start", window_from.to_string()),
                            ("End", window_to.to_string()),
                            ("Timezone", "UTC".to_string()),
                            ("Type", query_type.to_string()),
                            ("Page", page.to_string()),
                            ("PageSize", PAGE_SIZE.to_string()),
                        ],
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(error) if crate::api::is_time_window_too_big(&error) => {
                        let [earlier, later] = split_window(window_from, window_to).ok_or(error)?;
                        windows.push(later);
                        windows.push(earlier);
                        break;
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "Failed to list Proton events (calendar {calendar_id}, type {query_type}, page {page}, window {window_from}..{window_to})"
                            )
                        });
                    }
                };
                let count = response.events.len();
                let has_more = response.more.map_or(count == PAGE_SIZE, |more| more == 1);
                for raw in response.events {
                    if !seen.insert(raw.id.clone()) {
                        continue;
                    }
                    match decrypt_event(pgp, &keys, &raw)
                        .and_then(|payloads| event_from_payloads(&raw, &payloads))
                    {
                        Ok(event) => result.push(event),
                        Err(error) => eprintln!(
                            "caldir-provider-proton: skipping malformed event {}: {error:#}",
                            raw.id
                        ),
                    }
                }
                if !has_more {
                    break;
                }
                page += 1;
            }
        }
    }
    Ok(result)
}

fn split_window(from: i64, to: i64) -> Option<[(i64, i64); 2]> {
    let width = to.checked_sub(from)?;
    if width <= 1 {
        return None;
    }
    let midpoint = from + width / 2;
    Some([(from, midpoint), (midpoint, to)])
}

pub async fn get_event(
    client: &mut ApiClient,
    calendar_id: &str,
    event_id: &str,
) -> Result<RawEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}");
    let response: EventResponse = client.get(&path, &[]).await?;
    Ok(response.event)
}

pub async fn create_event<P: PGPProviderSync>(
    client: &mut ApiClient,
    account: &UnlockedAccount<P>,
    pgp: &P,
    calendar_id: &str,
    mut event: Event,
) -> Result<Event> {
    let keys = unlock_calendar(client, account, pgp, calendar_id).await?;
    let cards = cards_from_event(&event)?;
    let session_key = pgp
        .session_key_generate(SessionKeyAlgorithm::Aes256)
        .context("Failed to generate Proton event session key")?;
    let key_packet = pgp
        .new_encryptor()
        .with_encryption_key(&keys.calendar_public)
        .encrypt_session_key(&session_key)
        .context("Failed to encrypt Proton event session key")?;
    let shared = encrypt_cards(pgp, &keys, &session_key, &cards)?;
    let mut remote_event = json!({
        "Permissions": 63,
        "IsOrganizer": 1,
        "SharedKeyPacket": base64::engine::general_purpose::STANDARD.encode(key_packet),
        "SharedEventContent": shared,
        "Notifications": notifications_from_event(&event),
        "Color": Value::Null,
    });
    if let Some(card) = signed_calendar_card(pgp, &keys, cards.calendar_signed.as_deref())? {
        remote_event["CalendarEventContent"] = json!([card]);
    }
    let body = json!({
        "MemberID": keys.member_id,
        "Events": [{ "Overwrite": 0, "Event": remote_event }]
    });
    let path = format!("/calendar/v1/{calendar_id}/events/sync");
    let response: Value = client.put(&path, body).await?;
    let id = sync_event_id(&response).context("Proton create response has no event ID")?;
    crate::content::set_item_ref(&mut event, id);
    Ok(event)
}

pub async fn update_event<P: PGPProviderSync>(
    client: &mut ApiClient,
    account: &UnlockedAccount<P>,
    pgp: &P,
    calendar_id: &str,
    mut event: Event,
) -> Result<Event> {
    let event_id = crate::content::item_ref(&event)
        .context("Proton event is missing X-PROTON-ITEM")?
        .to_string();
    let raw = get_event(client, calendar_id, &event_id).await?;
    guard_mutation(&raw)?;
    event.sequence = event
        .sequence
        .max(i32::try_from(raw.sequence.unwrap_or(0)).unwrap_or(i32::MAX))
        .saturating_add(1);
    let keys = unlock_calendar(client, account, pgp, calendar_id).await?;
    let packet = raw
        .shared_key_packet
        .as_deref()
        .context("Proton event has no shared key packet")?;
    let packet = base64::engine::general_purpose::STANDARD
        .decode(packet)
        .context("Proton event shared key packet is invalid")?;
    let session_key = pgp
        .new_decryptor()
        .with_decryption_key(&keys.calendar_private)
        .decrypt_session_key(packet)
        .context("Failed to recover Proton event session key")?;
    let cards = cards_from_event(&event)?;
    let shared = encrypt_cards(pgp, &keys, &session_key, &cards)?;
    let mut remote_event = json!({
        "Permissions": raw.permissions.unwrap_or(63),
        "IsOrganizer": raw.is_organizer.unwrap_or(1),
        "SharedEventContent": shared,
        "Notifications": notifications_from_event(&event),
        "Color": Value::Null,
    });
    if let Some(card) = signed_calendar_card(pgp, &keys, cards.calendar_signed.as_deref())? {
        remote_event["CalendarEventContent"] = json!([card]);
    }
    let body = json!({
        "MemberID": keys.member_id,
        "Events": [{ "ID": event_id, "Event": remote_event }]
    });
    let path = format!("/calendar/v1/{calendar_id}/events/sync");
    let _: Value = client.put(&path, body).await?;
    Ok(event)
}

pub async fn delete_event<P: PGPProviderSync>(
    client: &mut ApiClient,
    account: &UnlockedAccount<P>,
    pgp: &P,
    calendar_id: &str,
    event_id: &str,
) -> Result<()> {
    let raw = get_event(client, calendar_id, event_id).await?;
    guard_mutation(&raw)?;
    let keys = unlock_calendar(client, account, pgp, calendar_id).await?;
    let body = json!({
        "MemberID": keys.member_id,
        "Events": [{ "ID": event_id, "DeletionReason": 0 }]
    });
    let path = format!("/calendar/v1/{calendar_id}/events/sync");
    let _: Value = client.put(&path, body).await?;
    Ok(())
}

fn guard_mutation(raw: &RawEvent) -> Result<()> {
    if !raw.attendees_info.attendees.is_empty() || raw.is_organizer == Some(0) {
        bail!(
            "Proton attendee and invitation writes are not supported; this event was not changed"
        );
    }
    Ok(())
}

fn decrypt_event<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    event: &RawEvent,
) -> Result<Vec<String>> {
    let (shared_packet, shared_private) = match (
        event.shared_key_packet.as_deref(),
        event.address_key_packet.as_deref(),
    ) {
        (Some(packet), _) => (Some(packet), &keys.calendar_private),
        (None, Some(packet)) => (Some(packet), &keys.address_private),
        (None, None) => (None, &keys.calendar_private),
    };
    let mut payloads = decrypt_group(
        pgp,
        keys,
        &event.shared_events,
        shared_packet,
        shared_private,
    )?;
    payloads.extend(decrypt_group(
        pgp,
        keys,
        &event.calendar_events,
        event
            .calendar_key_packet
            .as_deref()
            .or(event.shared_key_packet.as_deref()),
        &keys.calendar_private,
    )?);
    payloads.extend(decrypt_group(
        pgp,
        keys,
        &event.attendees_events,
        shared_packet,
        shared_private,
    )?);
    Ok(payloads)
}

fn decrypt_group<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    payloads: &[EventPayload],
    key_packet: Option<&str>,
    private_key: &P::PrivateKey,
) -> Result<Vec<String>> {
    let needs_session_key = payloads.iter().any(|payload| matches!(payload.kind, 1 | 3));
    let session_key = if needs_session_key {
        let packet = key_packet.context("Encrypted Proton card has no key packet")?;
        let packet = base64::engine::general_purpose::STANDARD
            .decode(packet)
            .context("Invalid Proton event key packet")?;
        Some(
            pgp.new_decryptor()
                .with_decryption_key(private_key)
                .decrypt_session_key(packet)
                .context("Failed to decrypt Proton event session key")?,
        )
    } else {
        None
    };
    payloads
        .iter()
        .map(|payload| decrypt_payload(pgp, keys, session_key.as_ref(), payload))
        .collect()
}

fn decrypt_payload<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    session_key: Option<&P::SessionKey>,
    payload: &EventPayload,
) -> Result<String> {
    let bytes = if matches!(payload.kind, 1 | 3) {
        let session_key = session_key.context("Encrypted Proton card has no session key")?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&payload.data)
            .context("Invalid encrypted Proton card")?;
        pgp.new_decryptor()
            .with_session_key_ref(session_key)
            .decrypt(data, DataEncoding::Bytes)
            .context("Failed to decrypt Proton card")?
            .into_vec()
    } else {
        payload.data.as_bytes().to_vec()
    };
    if matches!(payload.kind, 2 | 3)
        && let Some(signature) = &payload.signature
        && pgp
            .new_verifier()
            .with_verification_key(&keys.address_public)
            .verify_detached(&bytes, signature, DataEncoding::Armor)
            .is_err()
    {
        eprintln!(
            "caldir-provider-proton: card signature could not be verified (author {})",
            payload.author
        );
    }
    String::from_utf8(bytes).context("Decrypted Proton card is not UTF-8")
}

fn encrypt_cards<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    session_key: &P::SessionKey,
    cards: &crate::mapping::EventCards,
) -> Result<Vec<Card>> {
    Ok(vec![
        sign_card(pgp, keys, &cards.shared_signed)?,
        encrypt_and_sign_card(pgp, keys, session_key, &cards.shared_encrypted)?,
    ])
}

fn sign_card<P: PGPProviderSync>(pgp: &P, keys: &CalendarKeys<P>, data: &str) -> Result<Card> {
    let signature = pgp
        .new_signer()
        .with_signing_key(&keys.address_private)
        .sign_detached(data, DataEncoding::Armor)
        .context("Failed to sign Proton calendar card")?;
    Ok(Card {
        kind: 2,
        data: data.to_string(),
        signature: String::from_utf8(signature).context("Armored signature is not UTF-8")?,
    })
}

fn encrypt_and_sign_card<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    session_key: &P::SessionKey,
    data: &str,
) -> Result<Card> {
    let encrypted = pgp
        .new_encryptor()
        .with_session_key_ref(session_key)
        .encrypt(data)
        .context("Failed to encrypt Proton calendar card")?;
    let signature = pgp
        .new_signer()
        .with_signing_key(&keys.address_private)
        .sign_detached(data, DataEncoding::Armor)
        .context("Failed to sign Proton calendar card")?;
    Ok(Card {
        kind: 3,
        data: base64::engine::general_purpose::STANDARD.encode(encrypted.as_data_packet()),
        signature: String::from_utf8(signature).context("Armored signature is not UTF-8")?,
    })
}

fn signed_calendar_card<P: PGPProviderSync>(
    pgp: &P,
    keys: &CalendarKeys<P>,
    data: Option<&str>,
) -> Result<Option<Card>> {
    data.map(|data| sign_card(pgp, keys, data)).transpose()
}

fn sync_event_id(value: &Value) -> Option<&str> {
    value
        .pointer("/Responses/0/Response/Event/ID")
        .or_else(|| value.pointer("/Responses/0/Response/Event/Id"))
        .or_else(|| value.pointer("/Responses/0/Event/ID"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::split_window;

    #[test]
    fn split_window_preserves_the_requested_range() {
        assert_eq!(split_window(100, 200), Some([(100, 150), (150, 200)]));
        assert_eq!(split_window(100, 201), Some([(100, 150), (150, 201)]));
    }

    #[test]
    fn split_window_stops_at_one_second() {
        assert_eq!(split_window(100, 101), None);
        assert_eq!(split_window(100, 100), None);
    }
}

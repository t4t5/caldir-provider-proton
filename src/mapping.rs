use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use caldir_core::{Event, EventTime, EventUid, RecurrenceId, Reminder};
use chrono::{DateTime, Utc};

use crate::calendar::RawEvent;
use crate::constants::ITEM_UID_PROPERTY;
use crate::content::set_item_ref;

#[derive(Debug, Clone)]
pub struct EventCards {
    pub shared_signed: String,
    pub shared_encrypted: String,
    pub calendar_signed: Option<String>,
}

pub fn event_from_payloads(raw: &RawEvent, payloads: &[String]) -> Result<Event> {
    let mut properties: BTreeMap<String, Vec<String>> = BTreeMap::new();
    insert_base_properties(&mut properties, raw)?;
    for payload in payloads {
        for line in extract_event_properties(payload) {
            let name = property_name(&line);
            if name.is_empty() || matches!(name.as_str(), "LAST-MODIFIED" | "CREATED") {
                continue;
            }
            if matches!(name.as_str(), "ATTENDEE" | "EXDATE" | "RDATE" | "ATTACH") {
                properties.entry(name).or_default().push(line);
            } else {
                properties.insert(name, vec![line]);
            }
        }
    }

    let mut ics =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:CALDIR-PROTON\r\nBEGIN:VEVENT\r\n");
    for lines in properties.values() {
        for line in lines {
            ics.push_str(line);
            ics.push_str("\r\n");
        }
    }
    ics.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    let events = Event::from_ics_str(&ics).context("Decrypted Proton cards are invalid ICS")?;
    let [event] = <[Result<Event, _>; 1]>::try_from(events)
        .map_err(|events| anyhow::anyhow!("Expected one Proton VEVENT, found {}", events.len()))?;
    let mut event = event.context("Failed to parse decrypted Proton VEVENT")?;
    if !raw.uid.is_empty() {
        event.uid = EventUid::new(&raw.uid);
    }
    if let Some(recurrence_id) = raw.recurrence_id {
        event.recurrence_id = Some(RecurrenceId::from_event_time(event_time_from_unix(
            recurrence_id,
            raw.start_timezone.as_deref(),
            raw.full_day != 0,
        )?));
    }
    if let Some(sequence) = raw.sequence {
        event.sequence = i32::try_from(sequence).unwrap_or(i32::MAX);
    }
    event.last_modified = raw
        .modify_time
        .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0));
    event.reminders = raw
        .notifications
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|notification| {
            let _notification_kind = notification.kind;
            reminder_from_trigger(&notification.trigger)
        })
        .collect();
    set_item_ref(&mut event, &raw.id);
    Ok(event)
}

pub fn cards_from_event(event: &Event) -> Result<EventCards> {
    if !event.attendees.is_empty() {
        bail!("Proton attendee and invitation writes are not supported");
    }
    let mut signed = Vec::new();
    let mut encrypted = Vec::new();
    let calendar_signed = vec![
        format!("STATUS:{}", event.status.as_ics_str()),
        format!("TRANSP:{}", event.availability.as_ics_str()),
    ];
    for line in extract_event_properties(&event.to_ics_string()) {
        let name = property_name(&line);
        match name.as_str() {
            "DTSTART" | "DTEND" | "RRULE" | "EXDATE" | "RDATE" | "ORGANIZER" | "SEQUENCE"
            | "UID" | "DTSTAMP" | "RECURRENCE-ID" => signed.push(line),
            "STATUS" | "TRANSP" => {}
            "LAST-MODIFIED" | "CREATED" => {}
            name if name.eq_ignore_ascii_case(ITEM_UID_PROPERTY) => {}
            _ => encrypted.push(line),
        }
    }
    Ok(EventCards {
        shared_signed: wrap_event(&signed),
        shared_encrypted: wrap_event(&encrypted),
        calendar_signed: Some(wrap_event(&calendar_signed)),
    })
}

pub fn notifications_from_event(event: &Event) -> Vec<serde_json::Value> {
    event
        .reminders
        .iter()
        .map(|reminder| {
            serde_json::json!({
                "Type": 1,
                "Trigger": trigger_from_reminder(*reminder),
            })
        })
        .collect()
}

fn insert_base_properties(
    properties: &mut BTreeMap<String, Vec<String>>,
    raw: &RawEvent,
) -> Result<()> {
    if raw.uid.is_empty() {
        bail!("Proton event {} has no UID", raw.id);
    }
    properties.insert("UID".into(), vec![format!("UID:{}", raw.uid)]);
    properties.insert(
        "DTSTART".into(),
        vec![format_time_property(
            "DTSTART",
            raw.start_time,
            raw.start_timezone.as_deref(),
            raw.full_day != 0,
        )?],
    );
    properties.insert(
        "DTEND".into(),
        vec![format_time_property(
            "DTEND",
            raw.end_time,
            raw.end_timezone.as_deref(),
            raw.full_day != 0,
        )?],
    );
    if let Some(rrule) = raw.rrule.as_deref().filter(|value| !value.is_empty()) {
        properties.insert(
            "RRULE".into(),
            vec![format!("RRULE:{}", rrule.trim_start_matches("RRULE:"))],
        );
    }
    if let Some(sequence) = raw.sequence {
        properties.insert("SEQUENCE".into(), vec![format!("SEQUENCE:{sequence}")]);
    }
    if let Some(recurrence_id) = raw.recurrence_id {
        properties.insert(
            "RECURRENCE-ID".into(),
            vec![format_time_property(
                "RECURRENCE-ID",
                recurrence_id,
                raw.start_timezone.as_deref(),
                raw.full_day != 0,
            )?],
        );
    }
    for exdate in &raw.exdates {
        properties
            .entry("EXDATE".into())
            .or_default()
            .push(format_time_property(
                "EXDATE",
                *exdate,
                raw.start_timezone.as_deref(),
                raw.full_day != 0,
            )?);
    }
    Ok(())
}

fn format_time_property(
    name: &str,
    timestamp: i64,
    timezone: Option<&str>,
    all_day: bool,
) -> Result<String> {
    let utc = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .with_context(|| format!("Proton timestamp {timestamp} is out of range"))?;
    if all_day {
        return Ok(format!("{name};VALUE=DATE:{}", utc.format("%Y%m%d")));
    }
    match timezone.filter(|zone| !zone.eq_ignore_ascii_case("UTC")) {
        Some(zone) => {
            let timezone: chrono_tz::Tz = zone
                .parse()
                .with_context(|| format!("Unknown Proton timezone: {zone}"))?;
            Ok(format!(
                "{name};TZID={zone}:{}",
                utc.with_timezone(&timezone).format("%Y%m%dT%H%M%S")
            ))
        }
        None => Ok(format!("{name}:{}", utc.format("%Y%m%dT%H%M%SZ"))),
    }
}

fn event_time_from_unix(
    timestamp: i64,
    timezone: Option<&str>,
    all_day: bool,
) -> Result<EventTime> {
    let utc = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .with_context(|| format!("Proton timestamp {timestamp} is out of range"))?;
    if all_day {
        return Ok(EventTime::Date(utc.date_naive()));
    }
    match timezone.filter(|zone| !zone.eq_ignore_ascii_case("UTC")) {
        Some(zone) => {
            let timezone: chrono_tz::Tz = zone
                .parse()
                .with_context(|| format!("Unknown Proton timezone: {zone}"))?;
            Ok(EventTime::DateTimeZoned {
                datetime: utc.with_timezone(&timezone).naive_local(),
                tzid: zone.to_string(),
            })
        }
        None => Ok(EventTime::DateTimeUtc(utc)),
    }
}

fn extract_event_properties(ics: &str) -> Vec<String> {
    let logical = unfold_lines(ics);
    let mut in_event = false;
    let mut nested = 0_u32;
    let mut result = Vec::new();
    for line in logical {
        let upper = line.to_ascii_uppercase();
        if upper == "BEGIN:VEVENT" {
            in_event = true;
            continue;
        }
        if upper == "END:VEVENT" {
            break;
        }
        if !in_event {
            continue;
        }
        if upper.starts_with("BEGIN:") {
            nested += 1;
            continue;
        }
        if upper.starts_with("END:") && nested > 0 {
            nested -= 1;
            continue;
        }
        if nested == 0 && line.contains(':') {
            result.push(line);
        }
    }
    result
}

fn unfold_lines(ics: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for raw in ics.replace("\r\n", "\n").split('\n') {
        if raw.starts_with([' ', '\t']) {
            if let Some(previous) = result.last_mut() {
                previous.push_str(&raw[1..]);
            }
        } else if !raw.is_empty() {
            result.push(raw.to_string());
        }
    }
    result
}

fn property_name(line: &str) -> String {
    line.split([';', ':'])
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase()
}

fn wrap_event(properties: &[String]) -> String {
    let mut value =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:CALDIR-PROTON\r\nBEGIN:VEVENT\r\n");
    for property in properties {
        value.push_str(property);
        value.push_str("\r\n");
    }
    value.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    value
}

fn reminder_from_trigger(trigger: &str) -> Option<Reminder> {
    let raw = trigger.strip_prefix('-')?;
    let minutes = parse_iso_duration_minutes(raw)?;
    i64::try_from(minutes).ok().map(Reminder::from_minutes)
}

fn parse_iso_duration_minutes(raw: &str) -> Option<u64> {
    let body = raw.strip_prefix('P')?;
    if let Some(weeks) = body.strip_suffix('W') {
        return weeks.parse::<u64>().ok()?.checked_mul(7 * 24 * 60);
    }
    let (date, time) = body.split_once('T').unwrap_or((body, ""));
    let days = if date.is_empty() {
        0
    } else {
        date.strip_suffix('D')?.parse::<u64>().ok()?
    };
    let mut remaining = time;
    let mut hours: u64 = 0;
    let mut minutes: u64 = 0;
    let mut seconds: u64 = 0;
    for (unit, target) in [('H', &mut hours), ('M', &mut minutes), ('S', &mut seconds)] {
        if let Some(index) = remaining.find(unit) {
            *target = remaining[..index].parse().ok()?;
            remaining = &remaining[index + 1..];
        }
    }
    if !remaining.is_empty() || !seconds.is_multiple_of(60) {
        return None;
    }
    days.checked_mul(24 * 60)?
        .checked_add(hours.checked_mul(60)?)?
        .checked_add(minutes)?
        .checked_add(seconds / 60)
}

fn trigger_from_reminder(reminder: Reminder) -> String {
    let minutes = reminder.minutes_before_start.unsigned_abs();
    if minutes == 0 {
        return "-PT0S".to_string();
    }
    if minutes.is_multiple_of(7 * 24 * 60) {
        return format!("-P{}W", minutes / (7 * 24 * 60));
    }
    if minutes.is_multiple_of(24 * 60) {
        return format!("-P{}D", minutes / (24 * 60));
    }
    let hours = minutes / 60;
    let minutes = minutes % 60;
    let mut value = String::from("-PT");
    if hours > 0 {
        value.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        value.push_str(&format!("{minutes}M"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::Notification;
    use chrono::NaiveDateTime;

    fn raw_event() -> RawEvent {
        RawEvent {
            id: "event-id".into(),
            start_time: 1_783_245_600,
            end_time: 1_783_249_200,
            start_timezone: Some("Europe/London".into()),
            end_timezone: Some("Europe/London".into()),
            full_day: 0,
            uid: "uid@example.test".into(),
            rrule: None,
            recurrence_id: None,
            exdates: Vec::new(),
            modify_time: Some(1_783_245_000),
            sequence: Some(3),
            permissions: Some(63),
            is_organizer: Some(1),
            shared_key_packet: None,
            address_key_packet: None,
            calendar_key_packet: None,
            shared_events: Vec::new(),
            calendar_events: Vec::new(),
            attendees_events: Vec::new(),
            attendees_info: Default::default(),
            notifications: Some(vec![Notification {
                kind: 1,
                trigger: "-PT15M".into(),
            }]),
        }
    }

    #[test]
    fn merges_fragment_cards_with_metadata() {
        let fragment = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Encrypted title\r\nDESCRIPTION:Secret\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let event = event_from_payloads(&raw_event(), &[fragment.into()]).unwrap();
        assert_eq!(event.summary.as_deref(), Some("Encrypted title"));
        assert_eq!(event.description.as_deref(), Some("Secret"));
        assert_eq!(event.uid.as_str(), "uid@example.test");
        assert_eq!(event.sequence, 3);
        assert_eq!(event.reminders, vec![Reminder::from_minutes(15)]);
        assert_eq!(event.x_property(ITEM_UID_PROPERTY), Some("event-id"));
    }

    #[test]
    fn partitions_event_cards() {
        let mut event = Event::new(
            "Private",
            EventTime::DateTimeUtc(
                NaiveDateTime::parse_from_str("20260705T100000", "%Y%m%dT%H%M%S")
                    .unwrap()
                    .and_utc(),
            ),
        );
        event.uid = EventUid::new("uid@example.test");
        event.description = Some("Secret".into());
        set_item_ref(&mut event, "remote");
        let cards = cards_from_event(&event).unwrap();
        assert!(cards.shared_signed.contains("UID:uid@example.test"));
        assert!(cards.shared_encrypted.contains("SUMMARY:Private"));
        assert!(cards.shared_encrypted.contains("DESCRIPTION:Secret"));
        assert!(!cards.shared_encrypted.contains(ITEM_UID_PROPERTY));
    }

    #[test]
    fn parses_notification_durations() {
        assert_eq!(
            reminder_from_trigger("-P1DT2H30M"),
            Some(Reminder::from_minutes(1_590))
        );
        assert_eq!(trigger_from_reminder(Reminder::from_minutes(120)), "-PT2H");
    }
}

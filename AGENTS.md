## Sync behavior

The provider uses Proton's undocumented web API and Proton's public,
MIT-licensed Rust crypto crates. It identifies itself honestly with
`x-pm-appversion: Other`; it does not impersonate an official Proton client.

- `X-PROTON-ITEM` links a local VEVENT to Proton's event ID.
- Pulls query all four Proton calendar window types so recurring masters whose
  `DTSTART` predates the window are retained. Large ranges use bounded,
  concurrent one-year windows, with adaptive splitting if Proton lowers its
  limit; results are deduplicated after fetching.
- Event keys are loaded and decrypted only when the requested range contains
  remote events.
- `ModifyTime` becomes `LAST-MODIFIED`; recurring exceptions retain their
  `RECURRENCE-ID`.
- Display alarms map to Proton device notifications. Proton email and device
  notifications are both represented as caldir reminders on pull.
- Session tokens and the derived key-unlock secret are stored under
  `~/.config/caldir/providers/proton/` (or
  `$CALDIR_PROVIDER_STORAGE_DIR`) in owner-only files. Refresh-token rotation
  is persisted atomically.
- Reads decrypt shared, personal-calendar, and attendee cards. Mutations of
  events with attendees, or events where the current user is not organizer,
  are refused to avoid damaging invitation state.

## Integration test

The CRUD test is disabled unless `PROTON_TEST_EMAIL` and
`PROTON_TEST_PASSWORD` are set. A dedicated scratch account is strongly
recommended. If the account uses TOTP, also set
`PROTON_TEST_TOTP_SECRET` to its base32 authenticator secret. Two-password
accounts also require `PROTON_TEST_MAILBOX_PASSWORD`.

```bash
cargo test --test provider_crud -- --nocapture
```

## Limitations

- Proton does not publish or support this API for third parties, so endpoints
  can change without notice.
- FIDO2 authentication, human-verification solving, attendee/invite writes,
  RSVP, and calendar management are not implemented.
- Human-verification errors include Proton's available methods and web URL;
  complete the check in a browser, then retry from the same network.
- The derived local key secret is protected by filesystem permissions, not an
  OS keyring. Revoking the Proton session does not erase the local file.

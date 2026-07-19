use anyhow::Result;
use caldir_core::provider::ProviderStorage;
use caldir_core::rpc::ListCalendars;
use caldir_core::{CalendarConfig, ProviderSlug, RemoteConfig};

use crate::api::ApiClient;
use crate::calendar;
use crate::constants::PROVIDER_NAME;
use crate::content::normalize_color;
use crate::remote_config::ProtonRemoteConfig;
use crate::session::SessionStore;

pub async fn handle(cmd: ListCalendars) -> Result<Vec<CalendarConfig>> {
    let storage = ProviderStorage::for_provider(PROVIDER_NAME)?;
    let store = SessionStore::new(storage);
    let session = store.load(&cmd.account_identifier)?;
    let mut client = ApiClient::new(session, store)?;
    let mut calendars = calendar::list_calendars(&mut client).await?;
    calendars.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(calendars
        .into_iter()
        .map(|calendar| {
            let params = ProtonRemoteConfig::new(&cmd.account_identifier, &calendar.id)
                .into_remote_config_params();
            CalendarConfig::new(
                calendar.display_name().map(str::to_string),
                calendar.display_color().map(normalize_color),
                Some(calendar.read_only()),
                Some(RemoteConfig::new(ProviderSlug::from(PROVIDER_NAME), params)),
            )
        })
        .collect())
}

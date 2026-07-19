use anyhow::Result;
use caldir_core::Event;
use caldir_core::provider::ProviderStorage;
use caldir_core::rpc::CreateEvent;

use crate::api::ApiClient;
use crate::calendar;
use crate::constants::PROVIDER_NAME;
use crate::keys::unlock_account;
use crate::remote_config::ProtonRemoteConfig;
use crate::session::SessionStore;

pub async fn handle(cmd: CreateEvent) -> Result<Event> {
    let remote = ProtonRemoteConfig::try_from(&cmd.remote)?;
    let storage = ProviderStorage::for_provider(PROVIDER_NAME)?;
    let store = SessionStore::new(storage);
    let session = store.load(&remote.proton_account)?;
    let mut client = ApiClient::new(session.clone(), store)?;
    let pgp = proton_crypto::new_pgp_provider();
    let account = unlock_account(&mut client, &session, &pgp).await?;
    calendar::create_event(
        &mut client,
        &account,
        &pgp,
        &remote.proton_calendar,
        cmd.event,
    )
    .await
}

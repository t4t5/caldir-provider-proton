use anyhow::Result;
use caldir_core::provider::ProviderStorage;
use caldir_core::rpc::DeleteEvent;

use crate::api::ApiClient;
use crate::calendar;
use crate::constants::PROVIDER_NAME;
use crate::content::item_ref;
use crate::keys::unlock_account;
use crate::remote_config::ProtonRemoteConfig;
use crate::session::SessionStore;

pub async fn handle(cmd: DeleteEvent) -> Result<()> {
    let remote = ProtonRemoteConfig::try_from(&cmd.remote)?;
    let Some(event_id) = item_ref(&cmd.event).map(str::to_string) else {
        return Ok(());
    };
    let storage = ProviderStorage::for_provider(PROVIDER_NAME)?;
    let store = SessionStore::new(storage);
    let session = store.load(&remote.proton_account)?;
    let mut client = ApiClient::new(session.clone(), store)?;
    let pgp = proton_crypto::new_pgp_provider();
    let account = unlock_account(&mut client, &session, &pgp).await?;
    calendar::delete_event(
        &mut client,
        &account,
        &pgp,
        &remote.proton_calendar,
        &event_id,
    )
    .await
}

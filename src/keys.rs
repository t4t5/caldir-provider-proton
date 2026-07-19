use anyhow::{Context, Result, bail};
use base64::Engine as _;
use proton_crypto::crypto::PGPProviderSync;
use proton_crypto_account::keys::{AddressKeys, LockedKey, UnlockedAddressKeys, UserKeys};
use proton_crypto_account::salts::{KeySecret, Salts};
use serde::Deserialize;

use crate::api::ApiClient;
use crate::session::Session;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserResponse {
    user: UserRecord,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserRecord {
    keys: Vec<LockedKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddressesResponse {
    addresses: Vec<AddressRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddressRecord {
    #[serde(rename = "ID")]
    id: String,
    keys: Vec<LockedKey>,
}

pub struct UnlockedAddress<P: PGPProviderSync> {
    pub id: String,
    pub keys: UnlockedAddressKeys<P>,
}

pub struct UnlockedAccount<P: PGPProviderSync> {
    pub addresses: Vec<UnlockedAddress<P>>,
}

impl<P: PGPProviderSync> UnlockedAccount<P> {
    pub fn address(&self, id: &str) -> Option<&UnlockedAddress<P>> {
        self.addresses.iter().find(|address| address.id == id)
    }
}

pub async fn derive_key_password(
    client: &mut ApiClient,
    mailbox_password: &str,
) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct SaltsResponse {
        key_salts: Salts,
    }

    let salts: SaltsResponse = client
        .get("/core/v4/keys/salts", &[])
        .await
        .context("Failed to load Proton key salts")?;
    let user: UserResponse = client
        .get("/core/v4/users", &[])
        .await
        .context("Failed to load Proton user keys")?;
    let srp = proton_crypto::new_srp_provider();
    for key in user.user.keys.iter().filter(|key| key.active) {
        if let Ok(secret) = salts
            .key_salts
            .salt_for_key(&srp, &key.id, mailbox_password.as_bytes())
        {
            return Ok(secret.as_bytes().to_vec());
        }
    }
    bail!("Failed to derive a key secret for any active Proton user key")
}

pub async fn unlock_account<P: PGPProviderSync>(
    client: &mut ApiClient,
    session: &Session,
    pgp: &P,
) -> Result<UnlockedAccount<P>> {
    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(&session.key_password)
        .context("Stored Proton key password is invalid")?;
    let secret = KeySecret::new(secret_bytes);
    let user: UserResponse = client
        .get("/core/v4/users", &[])
        .await
        .context("Failed to load Proton user keys")?;
    let user_result = UserKeys::new(user.user.keys).unlock(pgp, &secret);
    if user_result.unlocked_keys.is_empty() {
        bail!("Failed to unlock Proton user keys; reconnect the account");
    }

    let response: AddressesResponse = client
        .get("/core/v4/addresses", &[])
        .await
        .context("Failed to load Proton addresses")?;
    let mut addresses = Vec::new();
    for address in response.addresses {
        let result =
            AddressKeys::new(address.keys).unlock(pgp, &user_result.unlocked_keys, Some(&secret));
        if !result.unlocked_keys.is_empty() {
            addresses.push(UnlockedAddress {
                id: address.id,
                keys: result.unlocked_keys.into(),
            });
        }
    }
    if addresses.is_empty() {
        bail!("Failed to unlock any Proton address keys; reconnect the account");
    }
    Ok(UnlockedAccount { addresses })
}

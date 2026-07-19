use anyhow::Result;
use caldir_core::RemoteConfigParams;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtonRemoteConfig {
    pub proton_account: String,
    pub proton_calendar: String,
}

impl ProtonRemoteConfig {
    pub fn new(account: impl Into<String>, calendar: impl Into<String>) -> Self {
        Self {
            proton_account: account.into(),
            proton_calendar: calendar.into(),
        }
    }

    pub fn into_remote_config_params(self) -> RemoteConfigParams {
        let mut params = RemoteConfigParams::new();
        params.insert(
            "proton_account".to_string(),
            toml::Value::String(self.proton_account),
        );
        params.insert(
            "proton_calendar".to_string(),
            toml::Value::String(self.proton_calendar),
        );
        params
    }
}

impl TryFrom<&RemoteConfigParams> for ProtonRemoteConfig {
    type Error = anyhow::Error;

    fn try_from(params: &RemoteConfigParams) -> Result<Self> {
        let proton_account = params
            .get("proton_account")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing required field: proton_account"))?
            .to_string();
        let proton_calendar = params
            .get("proton_calendar")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing required field: proton_calendar"))?
            .to_string();
        Ok(Self {
            proton_account,
            proton_calendar,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let original = ProtonRemoteConfig::new("alice@proton.me", "calendar-id");
        let restored =
            ProtonRemoteConfig::try_from(&original.clone().into_remote_config_params()).unwrap();
        assert_eq!(restored.proton_account, original.proton_account);
        assert_eq!(restored.proton_calendar, original.proton_calendar);
    }
}

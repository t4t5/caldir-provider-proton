pub const PROVIDER_NAME: &str = "proton";
pub const PROTON_API_URL: &str = "https://mail.proton.me/api";
pub const APP_VERSION: &str = "Other";
pub const USER_AGENT: &str = concat!("caldir-provider-proton/", env!("CARGO_PKG_VERSION"));
pub const ITEM_UID_PROPERTY: &str = "X-PROTON-ITEM";
pub const PAGE_SIZE: usize = 100;

#[cfg(test)]
mod tests {
    use super::PAGE_SIZE;

    #[test]
    fn proton_page_size_is_within_api_bounds() {
        assert!((1..=100).contains(&PAGE_SIZE));
    }
}

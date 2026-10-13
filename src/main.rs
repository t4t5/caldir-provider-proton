mod api;
mod auth;
mod calendar;
mod commands;
mod constants;
mod content;
mod hv;
#[cfg(feature = "hv")]
mod hv_window;
mod keys;
mod mapping;
mod remote_config;
mod session;

use std::env;

use async_trait::async_trait;
use caldir_core::provider::{self, ProviderStorage};
use caldir_core::rpc::{
    Connect, ConnectResponse, CreateEvent, DeleteEvent, ListCalendars, ListEvents, UpdateEvent,
};
use caldir_core::{CalendarConfig, Event};

struct ProtonProvider;

#[async_trait]
impl provider::Handler for ProtonProvider {
    async fn connect(&self, cmd: Connect) -> provider::Result<ConnectResponse> {
        Ok(commands::connect::handle(cmd).await?)
    }

    async fn list_calendars(&self, cmd: ListCalendars) -> provider::Result<Vec<CalendarConfig>> {
        Ok(commands::list_calendars::handle(cmd).await?)
    }

    async fn list_events(&self, cmd: ListEvents) -> provider::Result<Vec<Event>> {
        Ok(commands::list_events::handle(cmd).await?)
    }

    async fn create_event(&self, cmd: CreateEvent) -> provider::Result<Event> {
        Ok(commands::create_event::handle(cmd).await?)
    }

    async fn update_event(&self, cmd: UpdateEvent) -> provider::Result<Event> {
        Ok(commands::update_event::handle(cmd).await?)
    }

    async fn delete_event(&self, cmd: DeleteEvent) -> provider::Result<()> {
        Ok(commands::delete_event::handle(cmd).await?)
    }
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    if arguments
        .next()
        .is_some_and(|argument| argument == hv::HELPER_FLAG)
    {
        #[cfg(feature = "hv")]
        hv_window::run_from_args(arguments);
        #[cfg(not(feature = "hv"))]
        {
            eprintln!("hv: unavailable: this build does not include the `hv` feature");
            std::process::exit(3);
        }
    }
    run_provider();
}

#[tokio::main(flavor = "current_thread")]
async fn run_provider() {
    // Drop an abandoned 2FA login so its password doesn't stay on disk.
    if let Ok(storage) = ProviderStorage::for_provider(constants::PROVIDER_NAME) {
        let _ = session::SessionStore::new(storage).discard_stale_pending();
    }
    provider::run_provider(ProtonProvider).await;
}

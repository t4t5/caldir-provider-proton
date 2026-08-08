use std::env;
use std::panic;
use std::process;
use std::time::{Duration, Instant};

use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::WebViewBuilder;
use wry::http::Request;

const CAPTURE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const INITIALIZATION_SCRIPT: &str = r#"
window.addEventListener("message", (event) => {
    let message = event.data;
    if (typeof message === "string") {
        try {
            message = JSON.parse(message);
        } catch {
            return;
        }
    }
    if (
        event.source === window &&
        message?.type === "HUMAN_VERIFICATION_SUCCESS" &&
        message?.payload?.type === "captcha" &&
        typeof message?.payload?.token === "string" &&
        message.payload.token.length > 0
    ) {
        window.ipc.postMessage(message.payload.token);
    }
});
"#;

#[derive(Debug)]
enum UserEvent {
    Solved(String),
}

fn main() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(token) = arguments.next() else {
        fail(2, "usage", "expected one challenge token");
    };
    if arguments.next().is_some() || token.is_empty() {
        fail(2, "usage", "expected one non-empty challenge token");
    }
    let Some(token) = token.to_str() else {
        fail(2, "usage", "challenge token is not valid UTF-8");
    };

    #[cfg(target_os = "linux")]
    prepare_linux_webview();

    panic::set_hook(Box::new(|info| {
        eprintln!("hv: unavailable: {info}");
    }));
    if panic::catch_unwind(|| run(token)).is_err() {
        process::exit(3);
    }
}

#[cfg(target_os = "linux")]
fn prepare_linux_webview() {
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        fail(3, "unavailable", "no graphical display is available");
    }
    set_default_env("GDK_BACKEND", "x11");
    set_default_env("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    set_default_env("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
}

#[cfg(target_os = "linux")]
fn set_default_env(key: &str, value: &str) {
    if env::var_os(key).is_none() {
        // This process is still single-threaded; the variables must be set before GTK starts.
        unsafe { env::set_var(key, value) };
    }
}

fn run(token: &str) -> ! {
    let mut url = reqwest::Url::parse("https://verify.proton.me/")
        .expect("the hard-coded Proton verification URL is valid");
    url.query_pairs_mut()
        .append_pair("methods", "captcha")
        .append_pair("token", token);

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("Proton human verification")
        .with_inner_size(LogicalSize::new(520.0, 680.0))
        .build(&event_loop)
        .unwrap_or_else(|error| {
            fail(
                3,
                "unavailable",
                &format!("window creation failed: {error}"),
            )
        });

    let builder = WebViewBuilder::new()
        .with_initialization_script(INITIALIZATION_SCRIPT)
        .with_ipc_handler(move |request: Request<String>| {
            let token = request.body();
            if !token.is_empty() && !token.contains(['\r', '\n']) {
                let _ = proxy.send_event(UserEvent::Solved(token.clone()));
            }
        })
        .with_url(url.as_str());

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let _webview = builder.build(&window).unwrap_or_else(|error| {
        fail(
            3,
            "unavailable",
            &format!("webview creation failed: {error}"),
        )
    });

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let _webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;

        let container = window
            .default_vbox()
            .unwrap_or_else(|| fail(3, "unavailable", "GTK window has no default container"));
        builder.build_gtk(container).unwrap_or_else(|error| {
            fail(
                3,
                "unavailable",
                &format!("webview creation failed: {error}"),
            )
        })
    };

    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(deadline);
        match event {
            Event::UserEvent(UserEvent::Solved(token)) => {
                println!("{token}");
                *control_flow = ControlFlow::ExitWithCode(0);
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                eprintln!("hv: cancelled: verification window was closed");
                *control_flow = ControlFlow::ExitWithCode(4);
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. })
                if Instant::now() >= deadline =>
            {
                eprintln!("hv: network: no verification token received within five minutes");
                *control_flow = ControlFlow::ExitWithCode(5);
            }
            _ => {}
        }
    });
}

fn fail(code: i32, category: &str, detail: &str) -> ! {
    eprintln!("hv: {category}: {detail}");
    process::exit(code);
}

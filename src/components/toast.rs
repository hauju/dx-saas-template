use std::collections::HashMap;

use dioxus::prelude::*;

/// Toast severity level, mapped to DaisyUI alert classes.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ToastLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl ToastLevel {
    fn css_class(self) -> &'static str {
        match self {
            ToastLevel::Info => "alert-info",
            ToastLevel::Success => "alert-success",
            ToastLevel::Warning => "alert-warning",
            ToastLevel::Error => "alert-error",
        }
    }
}

/// A single toast notification.
#[derive(Debug, Clone)]
struct ToastData {
    message: String,
    level: ToastLevel,
}

/// Manages active toast notifications.
#[derive(Default, Clone)]
pub struct ToastManager {
    toasts: HashMap<usize, ToastData>,
    next_id: usize,
}

impl ToastManager {
    fn add(&mut self, message: String, level: ToastLevel) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.toasts.insert(id, ToastData { message, level });
        id
    }

    fn remove(&mut self, id: usize) {
        self.toasts.remove(&id);
    }
}

/// Show a toast from anywhere in the app.
pub fn show_toast(message: impl Into<String>, level: ToastLevel) {
    let duration_ms = match level {
        ToastLevel::Error => 8000,
        ToastLevel::Warning => 6000,
        _ => 4000,
    };
    show_toast_with_duration(message, level, duration_ms);
}

/// Show a toast with a custom duration in milliseconds.
pub fn show_toast_with_duration(message: impl Into<String>, level: ToastLevel, duration_ms: u64) {
    let message = message.into();
    spawn(async move {
        let mut manager = consume_context::<Signal<ToastManager>>();
        let id = manager.write().add(message, level);

        // Auto-remove after duration using a platform-agnostic sleep
        #[cfg(feature = "server")]
        tokio::time::sleep(std::time::Duration::from_millis(duration_ms)).await;

        #[cfg(not(feature = "server"))]
        gloo_timers::future::TimeoutFuture::new(duration_ms as u32).await;

        manager.write().remove(id);
    });
}

/// Renders the toast stack. Place this once near the root of your app.
#[component]
pub fn ToastProvider() -> Element {
    let mut manager = use_context::<Signal<ToastManager>>();

    let toasts: Vec<(usize, String, ToastLevel)> = manager
        .read()
        .toasts
        .iter()
        .map(|(id, t)| (*id, t.message.clone(), t.level))
        .collect();

    rsx! {
        div { class: "toast toast-end toast-bottom z-50",
            for (id, message, level) in toasts {
                div {
                    key: "{id}",
                    class: "alert {level.css_class()} shadow-lg cursor-pointer",
                    onclick: move |_| {
                        manager.write().remove(id);
                    },
                    span { "{message}" }
                }
            }
        }
    }
}

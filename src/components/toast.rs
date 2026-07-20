#![allow(dead_code)]
//! Toast notifications — template hook ready for downstream features.

use std::collections::HashMap;

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::{LdCircleCheck, LdCircleX, LdInfo, LdTriangleAlert, LdX};

/// Toast severity level, mapped to a status icon and accent color.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToastLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl ToastLevel {
    fn accent_class(self) -> &'static str {
        match self {
            ToastLevel::Info => "text-info bg-info/10",
            ToastLevel::Success => "text-success bg-success/10",
            ToastLevel::Warning => "text-warning bg-warning/10",
            ToastLevel::Error => "text-error bg-error/10",
        }
    }

    fn icon(self) -> Element {
        match self {
            ToastLevel::Info => rsx! { Icon { class: "size-3.5", icon: LdInfo } },
            ToastLevel::Success => rsx! { Icon { class: "size-3.5", icon: LdCircleCheck } },
            ToastLevel::Warning => rsx! { Icon { class: "size-3.5", icon: LdTriangleAlert } },
            ToastLevel::Error => rsx! { Icon { class: "size-3.5", icon: LdCircleX } },
        }
    }
}

/// A single toast notification.
#[derive(Debug, Clone)]
struct ToastData {
    message: String,
    level: ToastLevel,
    removing: bool,
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
        self.toasts.insert(
            id,
            ToastData {
                message,
                level,
                removing: false,
            },
        );
        id
    }

    fn mark_removing(&mut self, id: usize) {
        if let Some(toast) = self.toasts.get_mut(&id) {
            toast.removing = true;
        }
    }

    fn remove(&mut self, id: usize) {
        self.toasts.remove(&id);
    }
}

/// Duration of the exit animation, kept in sync with `.animate-toast-out`.
const EXIT_ANIMATION_MS: u64 = 300;

/// Platform-agnostic sleep used to schedule auto-dismiss and exit animations.
async fn sleep(ms: u64) {
    #[cfg(feature = "server")]
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;

    #[cfg(not(feature = "server"))]
    gloo_timers::future::TimeoutFuture::new(ms as u32).await;
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

        sleep(duration_ms).await;

        // Play the exit animation, then drop the toast once it finishes.
        manager.write().mark_removing(id);
        sleep(EXIT_ANIMATION_MS).await;
        manager.write().remove(id);
    });
}

/// Renders the toast stack. Place this once near the root of your app.
#[component]
pub fn ToastProvider() -> Element {
    let mut manager = use_context::<Signal<ToastManager>>();

    let mut toasts: Vec<(usize, String, ToastLevel, bool)> = manager
        .read()
        .toasts
        .iter()
        .map(|(id, t)| (*id, t.message.clone(), t.level, t.removing))
        .collect();
    toasts.sort_by_key(|(id, ..)| *id);

    rsx! {
        div {
            class: "toast toast-end toast-bottom z-50",
            role: "status",
            "aria-live": "polite",
            "aria-atomic": "false",
            for (id, message, level, removing) in toasts {
                div {
                    key: "{id}",
                    class: format!(
                        "group flex w-80 max-w-[calc(100vw-2rem)] cursor-pointer items-center gap-3 whitespace-normal rounded-xl border border-base-content/10 bg-base-100/85 px-4 py-3 shadow-lg backdrop-blur-xl {}",
                        if removing { "animate-toast-out" } else { "animate-toast-in" },
                    ),
                    onclick: move |_| {
                        manager.write().mark_removing(id);
                        spawn(async move {
                            sleep(EXIT_ANIMATION_MS).await;
                            manager.write().remove(id);
                        });
                    },
                    div {
                        class: format!(
                            "flex size-6 shrink-0 items-center justify-center rounded-full {}",
                            level.accent_class(),
                        ),
                        {level.icon()}
                    }
                    span { class: "min-w-0 flex-1 text-sm font-medium leading-snug text-base-content",
                        "{message}"
                    }
                    div {
                        class: "shrink-0 rounded-md p-1 text-base-content/40 opacity-0 transition-opacity group-hover:opacity-100",
                        Icon { class: "size-3.5", icon: LdX }
                    }
                }
            }
        }
    }
}

use dioxus::prelude::*;
use dioxus_free_icons::{Icon, icons::ld_icons::*};

/// Light/dark theme toggle. Flips `data-theme` on `<html>` and persists the
/// choice to `localStorage` so the boot script (see `THEME_BOOTSTRAP_JS`) can
/// restore it on the next load. Renders as a plain button meant to sit inside
/// a DaisyUI menu `li`.
#[component]
pub fn ThemeToggle() -> Element {
    // Boot script sets `data-theme` before first paint; sync our label to it
    // after hydration so it reflects the real current theme.
    let mut theme = use_signal(|| "dark".to_string());

    use_effect(move || {
        spawn(async move {
            if let Ok(current) = document::eval(
                "return document.documentElement.getAttribute('data-theme') || 'dark';",
            )
            .join::<String>()
            .await
                && (current == "light" || current == "dark")
            {
                theme.set(current);
            }
        });
    });

    let is_dark = theme() == "dark";

    let toggle = move |_| {
        let next = if theme() == "dark" { "light" } else { "dark" };
        theme.set(next.to_string());
        let dark = next == "dark";
        let _ = document::eval(&format!(
            "(function(){{var r=document.documentElement;var d={dark};\
             r.setAttribute('data-theme', d?'dark':'light');\
             r.setAttribute('data-color-mode', d?'dark':'light');\
             r.style.colorScheme=d?'dark':'light';\
             try{{localStorage.setItem('theme', d?'dark':'light');}}catch(e){{}}}})();"
        ));
    };

    rsx! {
        button { onclick: toggle,
            if is_dark {
                Icon { icon: LdMoon, width: 16, height: 16 }
                "Theme: dark"
            } else {
                Icon { icon: LdSun, width: 16, height: 16 }
                "Theme: light"
            }
        }
    }
}

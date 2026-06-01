use adw::{prelude::*, Application};
use gtk::{Box, Button, Label, ListBox, Orientation};
use std::collections::HashMap;

const APP_ID: &str = "dev.neoncore.atlas";

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    let i18n = I18n::from_env();
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(i18n.tr("app-name"))
        .default_width(980)
        .default_height(680)
        .build();

    let root = Box::new(Orientation::Horizontal, 0);
    let sidebar = ListBox::new();
    for key in [
        "nav-dashboard",
        "nav-nodes",
        "nav-profiles",
        "nav-routing",
        "nav-logs",
        "nav-settings",
    ] {
        sidebar.append(&Label::new(Some(i18n.tr(key))));
    }

    let dashboard = Box::new(Orientation::Vertical, 12);
    dashboard.set_margin_top(24);
    dashboard.set_margin_bottom(24);
    dashboard.set_margin_start(24);
    dashboard.set_margin_end(24);
    dashboard.append(&Label::new(Some(i18n.tr("app-name"))));
    dashboard.append(&Label::new(Some(i18n.tr("connection-status-disconnected"))));
    dashboard.append(&Button::with_label(i18n.tr("connection-action-connect")));
    dashboard.append(&Label::new(Some(i18n.tr("nodes-empty-title"))));
    dashboard.append(&Label::new(Some(i18n.tr("nodes-empty-description"))));

    root.append(&sidebar);
    root.append(&dashboard);
    window.set_content(Some(&root));
    window.present();
}

struct AtlasDaemonClient;

impl AtlasDaemonClient {
    fn endpoint_description(&self) -> &'static str {
        "future Unix domain socket client for neoncore-daemon"
    }
}

struct I18n {
    messages: HashMap<&'static str, &'static str>,
}

impl I18n {
    fn from_env() -> Self {
        let locale = std::env::var("ATLAS_LOCALE").unwrap_or_else(|_| "en-AU".to_string());
        let source = match locale.as_str() {
            "zh-Hans" => include_str!("../i18n/zh-Hans.ftl"),
            "en-XA" => include_str!("../i18n/en-XA.ftl"),
            _ => include_str!("../i18n/en-AU.ftl"),
        };
        Self {
            messages: source
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect(),
        }
    }

    fn tr(&self, key: &str) -> &str {
        self.messages.get(key).copied().unwrap_or(key)
    }
}

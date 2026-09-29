use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use suba_core::{Format, ProtocolSupport};

use crate::{dto::Authenticated, AppState};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public status
#[derive(Serialize, Deserialize)]
pub struct SystemStatus {
    version: String,
    administrator_configured: bool,
}

/// Authenticated status: what this instance is, and what it can serve.
#[derive(Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub administrator_configured: bool,
    /// The document formats this build writes.
    ///
    /// Compiled, not configured: a format whose dialect is behind a feature that
    /// is off is absent here, so a client that reads this list never asks for
    /// something this instance cannot answer.
    pub formats: Vec<FormatView>,
}

/// One format, as the API describes it.
///
/// Written, never read: the names are the ones the model spells, so this is a
/// response and not a request body.
#[derive(Debug, Serialize)]
pub struct FormatView {
    /// The name it is asked for by.
    pub name: &'static str,
    /// The directions it can write.
    pub intents: Vec<&'static str>,
    /// The protocols it can write, so that a caller can tell what a format will
    /// leave out **before** asking for a document.
    pub protocols: ProtocolsView,
}

/// Which protocols a format has a representation for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case", tag = "support")]
pub enum ProtocolsView {
    /// None of them are left out.
    Everything,
    /// These, and no others.
    Only { kinds: Vec<&'static str> },
}

pub async fn ping() -> &'static str {
    "SubA"
}

pub async fn status(State(state): State<AppState>) -> Json<SystemStatus> {
    Json(SystemStatus {
        version: VERSION.to_string(),
        administrator_configured: state.settings().administrator().await.is_some(),
    })
}

pub async fn info(_auth: Authenticated, State(state): State<AppState>) -> Json<SystemInfo> {
    Json(SystemInfo {
        version: VERSION.to_string(),
        administrator_configured: state.settings().administrator().await.is_some(),
        formats: formats(),
    })
}

/// What this build can write, in the order the formats are listed in.
fn formats() -> Vec<FormatView> {
    Format::all()
        .iter()
        .map(|format| {
            let descriptor = format.descriptor();

            FormatView {
                name: format.as_str(),
                intents: descriptor
                    .intents
                    .iter()
                    .map(|intent| intent.as_str())
                    .collect(),
                protocols: match descriptor.protocols {
                    ProtocolSupport::Everything => ProtocolsView::Everything,
                    ProtocolSupport::Only(kinds) => ProtocolsView::Only {
                        kinds: kinds.iter().map(|kind| kind.as_str()).collect(),
                    },
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capability_list_says_what_each_format_writes() {
        let formats = formats();
        assert!(!formats.is_empty(), "a build that serves nothing is a bug");

        for format in &formats {
            assert!(!format.intents.is_empty(), "{format:?} writes no direction");
            assert!(
                Format::all()
                    .iter()
                    .any(|known| known.as_str() == format.name),
                "{:?} is not a format this build has",
                format.name
            );
        }
    }

    /// The name in the capability list is the name a request is made with: the
    /// one the format serializes as.
    #[test]
    fn the_listed_name_is_the_name_that_is_asked_for() {
        let spelled = serde_json::to_value(Format::all()).expect("the formats serialize");
        let spelled = spelled.as_array().expect("a list");

        assert_eq!(
            formats()
                .iter()
                .map(|format| format.name)
                .collect::<Vec<_>>(),
            spelled
                .iter()
                .map(|name| name.as_str().expect("a name"))
                .collect::<Vec<_>>()
        );
    }

    /// A format that leaves no protocol out says so rather than listing every
    /// protocol it knows.
    #[test]
    fn a_format_that_leaves_nothing_out_says_so() {
        for format in formats() {
            if let ProtocolsView::Only { kinds } = &format.protocols {
                assert!(!kinds.is_empty(), "{format:?} can write nothing");
            }
        }
    }
}

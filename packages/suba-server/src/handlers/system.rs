use axum::{extract::State, Json};
use garde::Validate;
use serde::{Deserialize, Serialize};
use suba_core::{ProtocolSupport, Target};

use crate::{
    dto::{Authenticated, Operator, ResponseResult, ValidatedJson},
    AppState,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public status
#[derive(Serialize, Deserialize)]
pub struct SystemStatus {
    version: String,
    administrator_configured: bool,
}

/// The operator-editable settings of this instance.
#[derive(Serialize)]
pub struct SystemSettings {
    subscription_prefix: String,
}

/// Only the delivery prefix can be changed through this resource.
#[derive(Deserialize, Validate)]
pub struct SystemSettingsChange {
    #[garde(length(min = 1, max = 64))]
    subscription_prefix: String,
}

/// Read the local instance settings, independent of the selected environment.
pub async fn settings(
    _auth: Authenticated,
    State(state): State<AppState>,
) -> ResponseResult<Json<SystemSettings>> {
    Ok(Json(SystemSettings {
        subscription_prefix: state.settings().subscription_prefix().await?,
    }))
}

/// Change the delivery segment; existing tokens remain valid at the new path.
pub async fn save_settings(
    _auth: Authenticated,
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<SystemSettingsChange>,
) -> ResponseResult<Json<SystemSettings>> {
    Ok(Json(SystemSettings {
        subscription_prefix: state
            .settings()
            .set_subscription_prefix(&payload.subscription_prefix)
            .await?,
    }))
}

/// Operator status: what this instance is, and what it can serve.
#[derive(Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub administrator_configured: bool,
    /// The conversion targets supported by this build.
    ///
    /// Compiled, not configured: a target whose dialect is behind a feature that
    /// is off is absent here, so a client that reads this list never asks for
    /// something this instance cannot answer.
    pub targets: Vec<TargetView>,
}

/// One target, as the API describes it.
///
/// Written, never read: the names are the ones the model spells, so this is a
/// response and not a request body.
#[derive(Debug, Serialize)]
pub struct TargetView {
    /// The name it is asked for by.
    pub name: &'static str,
    /// The directions it can write.
    pub intents: Vec<&'static str>,
    /// The protocols it can write, so that a caller can tell what a target will
    /// leave out **before** asking for a document.
    pub protocols: ProtocolsView,
}

/// Which protocols a target has a representation for.
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
        administrator_configured: !state.is_agent()
            && state.settings().administrator().await.is_some(),
    })
}

/// The machine this instance runs on: CPU, memory, disk and network.
pub async fn metrics(
    _auth: Operator,
    State(state): State<AppState>,
) -> ResponseResult<Json<crate::state::metrics::Metrics>> {
    let metrics = state.metrics();

    Ok(Json(
        tokio::task::spawn_blocking(move || metrics.sample()).await?,
    ))
}

pub async fn info(_auth: Operator, State(state): State<AppState>) -> Json<SystemInfo> {
    Json(SystemInfo {
        version: VERSION.to_string(),
        administrator_configured: !state.is_agent()
            && state.settings().administrator().await.is_some(),
        targets: if state.is_agent() {
            Vec::new()
        } else {
            targets()
        },
    })
}

/// What this build can write, in the order the targets are listed in.
fn targets() -> Vec<TargetView> {
    Target::all()
        .iter()
        .map(|target| {
            let descriptor = target.descriptor();

            TargetView {
                name: target.as_str(),
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
    fn the_capability_list_says_what_each_target_writes() {
        let targets = targets();
        assert!(!targets.is_empty(), "a build that serves nothing is a bug");

        for target in &targets {
            assert!(!target.intents.is_empty(), "{target:?} writes no direction");
            assert!(
                Target::all()
                    .iter()
                    .any(|known| known.as_str() == target.name),
                "{:?} is not a target this build has",
                target.name
            );
        }
    }

    /// The name in the capability list is the name a request is made with: the
    /// one the target serializes as.
    #[test]
    fn the_listed_name_is_the_name_that_is_asked_for() {
        let spelled = serde_json::to_value(Target::all()).expect("the targets serialize");
        let spelled = spelled.as_array().expect("a list");

        assert_eq!(
            targets()
                .iter()
                .map(|target| target.name)
                .collect::<Vec<_>>(),
            spelled
                .iter()
                .map(|name| name.as_str().expect("a name"))
                .collect::<Vec<_>>()
        );
    }

    /// A target that leaves no protocol out says so rather than listing every
    /// protocol it knows.
    #[test]
    fn a_target_that_leaves_nothing_out_says_so() {
        for target in targets() {
            if let ProtocolsView::Only { kinds } = &target.protocols {
                assert!(!kinds.is_empty(), "{target:?} can write nothing");
            }
        }
    }
}

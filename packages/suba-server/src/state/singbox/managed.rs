//! Pool users in the configuration the core runs, and the clients that reach
//! every user of an inbound.
//!
//! **Injected, never written back.** A pool user exists only in the assembled
//! document: the operator's configuration keeps its hand-written users and
//! nothing else, so the two never become two truths about one user.
//!
//! **A pool user's name is reserved on the whole document.** The core puts the
//! name into the connection's metadata, and `auth_user` rules, the log and the
//! stats all join on it, so a hand-written namesake in any inbound would be
//! counted as the same person. Inside one inbound a hand-written credential
//! equal to a pool user's is refused too: the core would keep one and drop the
//! other without a word.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use suba_core::proto::{write_link, Client, Host, Node};
use suba_singbox::users::{self, Protocol};

use crate::error::Error;
use crate::state::access::{Access, Entry};

/// The pool users one inbound of a configuration gets.
struct Planned {
    protocol: Protocol,
    users: Vec<PlannedUser>,
}

struct PlannedUser {
    name: String,
    via: Vec<String>,
    entry: Value,
}

/// What pools add to each inbound of `config`, by inbound index, and every
/// name that is a pool user's anywhere in it.
struct Plan {
    inbounds: BTreeMap<usize, Planned>,
    reserved: BTreeSet<String>,
}

fn plan(document: &Value, config: &str, access: &Access) -> Plan {
    let mut plan = Plan {
        inbounds: BTreeMap::new(),
        reserved: BTreeSet::new(),
    };
    let grants = access.grants();

    for (index, inbound) in inbounds(document).iter().enumerate() {
        let Some(tag) = inbound.get("tag").and_then(Value::as_str) else {
            continue;
        };
        // An inbound a pool cannot grant gets nothing, whatever a pool says:
        // the pool view reports it, and the core keeps serving what it had.
        let Ok(protocol) = users::grantable(inbound) else {
            continue;
        };
        let at = Entry {
            config: config.to_owned(),
            inbound: tag.to_owned(),
        };
        let planned: Vec<PlannedUser> = grants
            .iter()
            .filter(|grant| grant.entry == at)
            .filter_map(|grant| {
                let material = access.material(&grant.user, &grant.entry)?;
                Some(PlannedUser {
                    name: grant.user.clone(),
                    via: grant.via.clone(),
                    entry: users::user(protocol, inbound, &grant.user, &material),
                })
            })
            .collect();

        if !planned.is_empty() {
            plan.reserved
                .extend(planned.iter().map(|user| user.name.clone()));
            plan.inbounds.insert(
                index,
                Planned {
                    protocol,
                    users: planned,
                },
            );
        }
    }

    plan
}

/// Why a hand-written user cannot run beside the pool users, with the field.
fn conflict(plan: &Plan, index: usize, at: usize, user: &Value) -> Option<String> {
    if name_of(user).is_some_and(|name| plan.reserved.contains(name)) {
        return Some(format!(
            "inbounds[{index}].users[{at}].name: reserved for a pool user"
        ));
    }

    let planned = plan.inbounds.get(&index)?;
    let credential = users::credential(planned.protocol, user)?;
    planned
        .users
        .iter()
        .any(|pooled| users::credential(planned.protocol, &pooled.entry) == Some(credential))
        .then(|| format!("inbounds[{index}].users[{at}]: same credential as a pool user"))
}

/// The document with every pool user of `config` added to its inbound.
pub(super) fn inject(document: &Value, config: &str, access: &Access) -> Result<Value, Error> {
    let plan = plan(document, config, access);

    for (index, inbound) in inbounds(document).iter().enumerate() {
        for (at, user) in hand_written(inbound).iter().enumerate() {
            if let Some(fault) = conflict(&plan, index, at, user) {
                return Err(Error::Document(fault));
            }
        }
    }

    let mut document = document.clone();
    for (index, planned) in plan.inbounds {
        let inbound = &mut document["inbounds"][index];
        if !inbound.get("users").is_some_and(Value::is_array) {
            inbound["users"] = Value::Array(Vec::new());
        }
        let users = inbound["users"].as_array_mut().expect("an array of users");
        users.extend(planned.users.into_iter().map(|user| user.entry));
    }

    Ok(document)
}

/// Where a configuration stands against the core that runs.
pub(crate) enum Serving<'a> {
    /// The core runs this configuration, as this product.
    Running(&'a Value),
    /// The core does not run, or runs another configuration.
    Not { in_use: bool },
}

/// How far a pool user's credential has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    /// The running core has it.
    Applied,
    /// The running core has something else; a restart applies it.
    Pending,
    /// The configuration is in use and the core is not running.
    Stopped,
    /// Another configuration is in use.
    Unused,
}

/// One client node, or why there is none.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Export {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// `None` also when this build cannot write sing-box outbounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The users of one inbound, as an editor shows them.
#[derive(Debug, Serialize)]
pub(crate) struct InboundUsers {
    pub index: usize,
    pub tag: Option<String>,
    /// Why pools cannot grant this inbound, when they cannot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<&'static str>,
    /// The flow every VLESS user of it has to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<&'static str>,
    pub users: Vec<HandWritten>,
    pub managed: Vec<Managed>,
    /// Users the running core still has here that this configuration no
    /// longer gives it; a restart takes them away.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub departing: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HandWritten {
    pub index: usize,
    #[serde(flatten)]
    pub export: Export,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Managed {
    pub user: String,
    pub via: Vec<String>,
    pub state: State,
    #[serde(flatten)]
    pub export: Export,
}

/// Every user of every inbound of `config`, hand-written and pooled.
pub(crate) fn exports(
    document: &Value,
    config: &str,
    access: &Access,
    host: Result<&Host, &str>,
    serving: &Serving<'_>,
) -> Vec<InboundUsers> {
    let plan = plan(document, config, access);

    inbounds(document)
        .iter()
        .enumerate()
        .map(|(index, inbound)| {
            let tag = inbound.get("tag").and_then(Value::as_str);
            let written = hand_written(inbound);
            let users = written
                .iter()
                .enumerate()
                .map(|(at, user)| HandWritten {
                    index: at,
                    export: hand_written_export(inbound, written, at, host),
                    conflict: conflict(&plan, index, at, user),
                })
                .collect();

            let managed: Vec<Managed> = plan
                .inbounds
                .get(&index)
                .map(|planned| {
                    planned
                        .users
                        .iter()
                        .map(|user| Managed {
                            user: user.name.clone(),
                            via: user.via.clone(),
                            state: state(serving, tag, &user.entry),
                            export: export(
                                inbound,
                                &user.entry,
                                "users",
                                host,
                                tag.unwrap_or_default(),
                            ),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let departing = departing(serving, tag, written, &managed);

            InboundUsers {
                index,
                tag: tag.map(str::to_owned),
                refused: users::grantable(inbound).err(),
                flow: users::flow(inbound),
                users,
                managed,
                departing,
            }
        })
        .collect()
}

/// The client nodes of one pool user in `config`, each named after its inbound,
/// or why one cannot be.
pub(crate) fn nodes(
    document: &Value,
    config: &str,
    access: &Access,
    user: &str,
    host: Result<&Host, &str>,
) -> Vec<Result<Node<Client>, String>> {
    let plan = plan(document, config, access);

    plan.inbounds
        .iter()
        .filter_map(|(index, planned)| {
            let pooled = planned.users.iter().find(|pooled| pooled.name == user)?;
            let inbound = &inbounds(document)[*index];
            let tag = inbound
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Some(match host {
                Err(reason) => Err(format!("public-host: {reason}")),
                Ok(host) => users::client(inbound, &pooled.entry, "users", host, tag)
                    .map_err(|refused| refused.to_string()),
            })
        })
        .collect()
}

/// The grants of `config` that have no inbound a pool can give, and why.
pub(crate) fn unplaced(document: &Value, entry: &Entry) -> Option<&'static str> {
    match inbounds(document)
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(&entry.inbound))
    {
        None => Some("no inbound has this tag"),
        Some(inbound) => users::grantable(inbound).err(),
    }
}

fn hand_written_export(
    inbound: &Value,
    written: &[Value],
    at: usize,
    host: Result<&Host, &str>,
) -> Export {
    let path = format!("users[{at}]");
    let Some(name) = name_of(&written[at]) else {
        return refusal(format!(
            "{path}.name: a user without a name cannot be told apart; logs, auth_user and stats cannot see it either"
        ));
    };
    if written
        .iter()
        .filter(|user| name_of(user) == Some(name))
        .count()
        > 1
    {
        return refusal(format!("{path}.name: not unique in this inbound"));
    }

    let tag = inbound
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or_default();
    export(inbound, &written[at], &path, host, &format!("{tag}-{name}"))
}

fn export(
    inbound: &Value,
    user: &Value,
    path: &str,
    host: Result<&Host, &str>,
    name: &str,
) -> Export {
    let host = match host {
        Ok(host) => host,
        Err(reason) => return refusal(format!("public-host: {reason}")),
    };
    match users::client(inbound, user, path, host, name) {
        Err(refused) => refusal(refused.to_string()),
        Ok(node) => Export {
            link: write_link(&node).ok(),
            outbound: outbound(name, &node),
            reason: None,
        },
    }
}

#[cfg(feature = "singbox")]
fn outbound(tag: &str, node: &Node<Client>) -> Option<Value> {
    suba_singbox::outbound(tag, node).ok()
}

#[cfg(not(feature = "singbox"))]
fn outbound(_: &str, _: &Node<Client>) -> Option<Value> {
    None
}

fn refusal(reason: String) -> Export {
    Export {
        reason: Some(reason),
        ..Export::default()
    }
}

fn state(serving: &Serving<'_>, tag: Option<&str>, entry: &Value) -> State {
    match serving {
        Serving::Not { in_use: true } => State::Stopped,
        Serving::Not { in_use: false } => State::Unused,
        Serving::Running(product) => match served(product, tag).contains(&entry) {
            true => State::Applied,
            false => State::Pending,
        },
    }
}

/// Names the running core serves here that neither this configuration's own
/// users nor its pool users have any more.
fn departing(
    serving: &Serving<'_>,
    tag: Option<&str>,
    written: &[Value],
    managed: &[Managed],
) -> Vec<String> {
    let Serving::Running(product) = serving else {
        return Vec::new();
    };

    served(product, tag)
        .into_iter()
        .filter_map(name_of)
        .filter(|name| !written.iter().any(|user| name_of(user) == Some(name)))
        .filter(|name| !managed.iter().any(|kept| kept.user == *name))
        .map(str::to_owned)
        .collect()
}

/// The users the product gives the inbound tagged `tag`.
fn served<'a>(product: &'a Value, tag: Option<&str>) -> Vec<&'a Value> {
    inbounds(product)
        .iter()
        .find(|inbound| tag.is_some() && inbound.get("tag").and_then(Value::as_str) == tag)
        .map(|inbound| hand_written(inbound).iter().collect())
        .unwrap_or_default()
}

fn inbounds(document: &Value) -> &[Value] {
    document
        .get("inbounds")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn hand_written(inbound: &Value) -> &[Value] {
    inbound
        .get("users")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The name the core puts in a connection's metadata: `name`, or `username`
/// for the protocols that have no name. The core reads keys without regard to
/// case, so this does too.
fn name_of(user: &Value) -> Option<&str> {
    user.as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("name") || key.eq_ignore_ascii_case("username"))
        .and_then(|(_, value)| value.as_str())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::state::access::{Pool, User};

    const PRIVATE_KEY: &str = "UPLJ7jF8V4gCQx8Fq4aJ3ux3Tx7GgSj2dX8JX0X7S2E";

    fn host() -> Host {
        Host::parse("proxy.example.com").unwrap()
    }

    fn document() -> Value {
        json!({"inbounds": [
            {
                "type": "vless", "tag": "vless-in", "listen_port": 443,
                "tls": {"enabled": true, "server_name": "www.example.org", "reality": {
                    "enabled": true, "private_key": PRIVATE_KEY, "short_id": ["0123abcd"],
                    "handshake": {"server": "www.example.org", "server_port": 443}
                }},
                "users": [{"name": "guest", "uuid": "c7d2e9f4-6a1b-4e3c-b5d8-0f2a4c6e8b03"}]
            },
            {"type": "trojan", "tag": "trojan-in", "listen_port": 8443, "tls": {"enabled": true}},
            {"type": "mixed", "tag": "mixed-in", "listen_port": 2080}
        ]})
    }

    fn entry(config: &str, inbound: &str) -> Entry {
        Entry {
            config: config.to_string(),
            inbound: inbound.to_string(),
        }
    }

    /// Alice through `standard` (both proxies, and the mixed inbound a pool
    /// cannot grant), bob through `light` in another configuration.
    fn access() -> Access {
        Access {
            users: BTreeMap::from([
                (
                    "alice".to_string(),
                    User {
                        pools: vec!["standard".into()],
                        secret: "11".repeat(32),
                        ..User::default()
                    },
                ),
                (
                    "bob".to_string(),
                    User {
                        pools: vec!["light".into()],
                        secret: "22".repeat(32),
                        ..User::default()
                    },
                ),
            ]),
            pools: BTreeMap::from([
                (
                    "standard".to_string(),
                    Pool {
                        entries: vec![
                            entry("server", "vless-in"),
                            entry("server", "trojan-in"),
                            entry("server", "mixed-in"),
                        ],
                    },
                ),
                (
                    "light".to_string(),
                    Pool {
                        entries: vec![entry("other", "trojan-in")],
                    },
                ),
            ]),
        }
    }

    fn names(document: &Value, index: usize) -> Vec<&str> {
        document["inbounds"][index]["users"]
            .as_array()
            .map(|users| users.iter().filter_map(name_of).collect())
            .unwrap_or_default()
    }

    #[test]
    fn pool_users_join_the_inbounds_of_their_configuration_only() {
        let injected = inject(&document(), "server", &access()).unwrap();

        assert_eq!(names(&injected, 0), ["guest", "alice"]);
        assert_eq!(
            names(&injected, 1),
            ["alice"],
            "bob's pool is another configuration's"
        );
        assert!(
            injected["inbounds"][2].get("users").is_none(),
            "a pool cannot turn authentication on"
        );
        assert_eq!(
            injected["inbounds"][0]["users"][1]["flow"],
            json!("xtls-rprx-vision"),
            "the flow the inbound's shape demands"
        );

        let elsewhere = inject(&document(), "other", &access()).unwrap();
        assert_eq!(names(&elsewhere, 0), ["guest"]);
        assert_eq!(names(&elsewhere, 1), ["bob"], "the same tags, as `other`");
    }

    #[test]
    fn a_hand_written_namesake_anywhere_is_refused_with_its_path() {
        let mut written = document();
        written["inbounds"][2]["users"] = json!([{"username": "alice", "password": "x"}]);

        let refused = inject(&written, "server", &access()).unwrap_err();

        assert!(matches!(
            refused,
            Error::Document(ref fault) if fault == "inbounds[2].users[0].name: reserved for a pool user"
        ));
    }

    #[test]
    fn a_hand_written_credential_equal_to_a_pool_users_is_refused() {
        let injected = inject(&document(), "server", &access()).unwrap();
        let pooled = injected["inbounds"][1]["users"][0]["password"].clone();
        let mut written = document();
        written["inbounds"][1]["users"] = json!([{"name": "carol", "password": pooled}]);

        let refused = inject(&written, "server", &access()).unwrap_err();

        assert!(matches!(
            refused,
            Error::Document(ref fault) if fault == "inbounds[1].users[0]: same credential as a pool user"
        ));
    }

    #[test]
    fn every_user_is_exported_or_says_why_not() {
        let mut written = document();
        written["inbounds"][0]["users"]
            .as_array_mut()
            .unwrap()
            .push(json!({"uuid": "5e8b1d3f-7c2a-4b9e-a6d0-1f3c5e7a9b04"}));

        let inbounds = exports(
            &written,
            "server",
            &access(),
            Ok(&host()),
            &Serving::Not { in_use: true },
        );

        let vless = &inbounds[0];
        assert_eq!(vless.flow, Some("xtls-rprx-vision"));
        assert!(vless.users[0]
            .export
            .link
            .as_deref()
            .unwrap()
            .contains("#vless-in-guest"));
        assert!(vless.users[1]
            .export
            .reason
            .as_deref()
            .unwrap()
            .starts_with("users[1].name"));
        assert_eq!(vless.managed[0].user, "alice");
        assert_eq!(vless.managed[0].state, State::Stopped);
        assert!(vless.managed[0]
            .export
            .link
            .as_deref()
            .unwrap()
            .ends_with("#vless-in"));
        assert_eq!(
            inbounds[2].refused,
            Some(users::grantable(&json!({"type": "mixed"})).unwrap_err())
        );

        let unset = exports(
            &written,
            "server",
            &access(),
            Err("not set"),
            &Serving::Not { in_use: false },
        );
        assert_eq!(
            unset[0].managed[0].export.reason.as_deref(),
            Some("public-host: not set")
        );
        assert_eq!(unset[0].managed[0].state, State::Unused);
    }

    #[test]
    fn the_running_product_decides_applied_pending_and_departing() {
        let mut product = inject(&document(), "server", &access()).unwrap();
        // The core started before bob had this inbound, with a user since dropped.
        product["inbounds"][1]["users"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "dave", "password": "old"}));
        let mut now = access();
        now.users.get_mut("alice").unwrap().secret = "33".repeat(32);

        let inbounds = exports(
            &document(),
            "server",
            &now,
            Ok(&host()),
            &Serving::Running(&product),
        );
        assert_eq!(
            inbounds[0].managed[0].state,
            State::Pending,
            "a new credential"
        );
        assert_eq!(inbounds[1].departing, ["dave"]);

        let same = exports(
            &document(),
            "server",
            &access(),
            Ok(&host()),
            &Serving::Running(&product),
        );
        assert_eq!(same[0].managed[0].state, State::Applied);
    }

    #[test]
    fn a_users_nodes_are_its_pool_users_in_one_configuration() {
        let nodes = super::nodes(&document(), "server", &access(), "alice", Ok(&host()));

        let names: Vec<String> = nodes
            .into_iter()
            .map(|node| node.unwrap().name.to_string())
            .collect();
        assert_eq!(names, ["vless-in", "trojan-in"]);
        assert!(super::nodes(&document(), "server", &access(), "bob", Ok(&host())).is_empty());
        assert!(
            super::nodes(&document(), "server", &access(), "alice", Err("not set"))
                .iter()
                .all(|node| node
                    .as_ref()
                    .is_err_and(|reason| reason == "public-host: not set"))
        );
    }
}

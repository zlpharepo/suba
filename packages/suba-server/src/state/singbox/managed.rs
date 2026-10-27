//! Managed users in the configuration the core runs, and the clients that
//! reach every user of an inbound.
//!
//! **Injected, never written back.** A managed user exists only in the
//! assembled document: the operator's configuration keeps its hand-written
//! users and nothing else, so the two never become two truths about one user.
//!
//! **A managed user's name is reserved on the whole document.** The core puts the
//! name into the connection's metadata, and `auth_user` rules, the log and the
//! stats all join on it, so a hand-written namesake in any inbound would be
//! counted as the same person. Inside one inbound a hand-written credential
//! equal to a managed user's is refused too: the core would keep one and drop
//! the other without a word.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use suba_core::proto::{write_link, Client, Host, Node};
use suba_singbox::users::{self, Protocol};

use crate::error::Error;
use crate::state::access::{Access, Entry};

/// The managed users one inbound of a configuration gets.
struct Planned {
    protocol: Protocol,
    users: Vec<PlannedUser>,
}

struct PlannedUser {
    name: String,
    entry: Value,
}

/// What users add to each inbound of `config`, by inbound index, and every
/// name that is a managed user's anywhere in it.
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
        // An inbound that cannot take users gets nothing, whatever a user
        // selects: the entry view reports it, and the core keeps serving what
        // it had.
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
                    entry: users::user(protocol, inbound, &grant.user, &material)?,
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

/// Why a hand-written user cannot run beside the managed users, with the field.
fn conflict(plan: &Plan, index: usize, at: usize, user: &Value) -> Option<String> {
    if name_of(user).is_some_and(|name| plan.reserved.contains(name)) {
        return Some(format!(
            "inbounds[{index}].users[{at}].name: reserved for a managed user"
        ));
    }

    let planned = plan.inbounds.get(&index)?;
    let credential = users::credential(planned.protocol, user)?;
    planned
        .users
        .iter()
        .any(|managed| users::credential(planned.protocol, &managed.entry) == Some(credential))
        .then(|| format!("inbounds[{index}].users[{at}]: same credential as a managed user"))
}

/// The document with every managed user of `config` added to its inbound.
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

/// How far a managed user's credential has got.
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
    /// Why an inbound cannot take users, when it cannot.
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
    pub state: State,
    #[serde(flatten)]
    pub export: Export,
}

/// Every user of every inbound of `config`, hand-written and managed.
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
                    export: hand_written_export(
                        inbound,
                        written,
                        at,
                        address_of(inbound, tag, config, access, host),
                    ),
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
                            state: state(serving, tag, &user.entry),
                            export: export(
                                address_of(inbound, tag, config, access, host),
                                &user.entry,
                                "users",
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

/// The client nodes of one managed user in `config`, each named after its
/// inbound, or why one cannot be.
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
            let managed = planned.users.iter().find(|held| held.name == user)?;
            let inbound = &inbounds(document)[*index];
            let tag = inbound
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let at = Entry {
                config: config.to_owned(),
                inbound: tag.to_owned(),
            };
            Some(match address(inbound, access.endpoint(&at), host) {
                Err(reason) => Err(reason),
                Ok(dialable) => users::client(
                    dialable.inbound(),
                    &managed.entry,
                    "users",
                    &dialable.host,
                    tag,
                )
                .map_err(|refused| refused.to_string()),
            })
        })
        .collect()
}

/// Where an entry stands against the configuration document it names.
pub(crate) enum Placement {
    /// The inbound is there and can take users.
    Placed,
    /// No inbound of this configuration has this tag.
    Unknown,
    /// The inbound is there but cannot take users.
    Refused(&'static str),
}

impl Placement {
    /// Why this entry cannot be exported, when it cannot.
    pub(crate) fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Placed => None,
            Self::Unknown => Some("no inbound has this tag"),
            Self::Refused(refused) => Some(refused),
        }
    }
}

/// Where the inbound `entry` names stands in `document`.
pub(crate) fn placement(document: &Value, entry: &Entry) -> Placement {
    match inbounds(document)
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(&entry.inbound))
    {
        None => Placement::Unknown,
        Some(inbound) => match users::grantable(inbound) {
            Ok(_) => Placement::Placed,
            Err(refused) => Placement::Refused(refused),
        },
    }
}

fn hand_written_export(
    inbound: &Value,
    written: &[Value],
    at: usize,
    dialable: Result<Dialable<'_>, String>,
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
    export(dialable, &written[at], &path, &format!("{tag}-{name}"))
}

fn export(dialable: Result<Dialable<'_>, String>, user: &Value, path: &str, name: &str) -> Export {
    let dialable = match dialable {
        Ok(dialable) => dialable,
        Err(reason) => return refusal(reason),
    };
    match users::client(dialable.inbound(), user, path, &dialable.host, name) {
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

/// The host a client dials for one inbound, with the port override already
/// applied to the inbound it will be read from.
///
/// The operator's address wins; otherwise the instance's public host is used.
/// The port is the inbound's own unless an override says otherwise, so a
/// forwarded or proxied entry can differ from what the core listens on.
struct Dialable<'a> {
    host: Host,
    inbound: std::borrow::Cow<'a, Value>,
}

impl Dialable<'_> {
    fn inbound(&self) -> &Value {
        &self.inbound
    }
}

fn address_of<'a>(
    inbound: &'a Value,
    tag: Option<&str>,
    config: &str,
    access: &Access,
    public: Result<&Host, &str>,
) -> Result<Dialable<'a>, String> {
    let at = Entry {
        config: config.to_owned(),
        inbound: tag.unwrap_or_default().to_owned(),
    };
    address(inbound, access.endpoint(&at), public)
}

fn address<'a>(
    inbound: &'a Value,
    endpoint: Option<&crate::state::access::Endpoint>,
    public: Result<&Host, &str>,
) -> Result<Dialable<'a>, String> {
    let host = match (
        endpoint.and_then(|endpoint| endpoint.address.as_deref()),
        public,
    ) {
        (Some(stored), _) => Host::parse(stored).map_err(|_| {
            "address: the stored address is not a host name or IP address".to_string()
        })?,
        (None, Ok(host)) => host.clone(),
        (None, Err(reason)) => return Err(format!("public-host: {reason}")),
    };
    let inbound = match endpoint.and_then(|endpoint| endpoint.port) {
        Some(port) => {
            let mut inbound = inbound.clone();
            inbound["listen_port"] = Value::from(port);
            std::borrow::Cow::Owned(inbound)
        }
        None => std::borrow::Cow::Borrowed(inbound),
    };

    Ok(Dialable { host, inbound })
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
/// users nor its managed users have any more.
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
    use crate::state::access::{Endpoint, User};

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
            {"type": "direct", "tag": "direct-in", "listen_port": 2080}
        ]})
    }

    fn entry(config: &str, inbound: &str) -> Entry {
        Entry {
            config: config.to_string(),
            inbound: inbound.to_string(),
        }
    }

    /// Alice uses both proxies and the inbound that cannot take users; bob
    /// uses another configuration's inbound.
    fn access() -> Access {
        Access {
            users: BTreeMap::from([
                (
                    "alice".to_string(),
                    User {
                        inbounds: vec![
                            entry("server", "vless-in"),
                            entry("server", "trojan-in"),
                            entry("server", "direct-in"),
                        ],
                        secret: "11".repeat(32),
                        ..User::default()
                    },
                ),
                (
                    "bob".to_string(),
                    User {
                        inbounds: vec![entry("other", "trojan-in")],
                        secret: "22".repeat(32),
                        ..User::default()
                    },
                ),
            ]),
            ..Access::default()
        }
    }

    /// The same users, with an address override on one of the inbounds.
    fn access_with_address() -> Access {
        let mut access = access();
        access.endpoints.insert(
            "server".to_string(),
            BTreeMap::from([(
                "trojan-in".to_string(),
                Endpoint {
                    address: Some("cdn.example.com".to_string()),
                    port: Some(8444),
                },
            )]),
        );
        access
    }

    fn names(document: &Value, index: usize) -> Vec<&str> {
        document["inbounds"][index]["users"]
            .as_array()
            .map(|users| users.iter().filter_map(name_of).collect())
            .unwrap_or_default()
    }

    #[test]
    fn managed_users_join_the_inbounds_of_their_configuration_only() {
        let injected = inject(&document(), "server", &access()).unwrap();

        assert_eq!(names(&injected, 0), ["guest", "alice"]);
        assert_eq!(
            names(&injected, 1),
            ["alice"],
            "bob's other inbound is another configuration's"
        );
        assert!(
            injected["inbounds"][2].get("users").is_none(),
            "an inbound users do not dial cannot take them"
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
            Error::Document(ref fault) if fault == "inbounds[2].users[0].name: reserved for a managed user"
        ));
    }

    #[test]
    fn a_hand_written_credential_equal_to_a_managed_users_is_refused() {
        let injected = inject(&document(), "server", &access()).unwrap();
        let pooled = injected["inbounds"][1]["users"][0]["password"].clone();
        let mut written = document();
        written["inbounds"][1]["users"] = json!([{"name": "carol", "password": pooled}]);

        let refused = inject(&written, "server", &access()).unwrap_err();

        assert!(matches!(
            refused,
            Error::Document(ref fault) if fault == "inbounds[1].users[0]: same credential as a managed user"
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
            Some(users::grantable(&json!({"type": "direct"})).unwrap_err())
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
    fn a_users_nodes_are_its_managed_users_in_one_configuration() {
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

    /// A stored address replaces the public host for the clients that reach
    /// that one inbound; a stored port replaces what the inbound listens on,
    /// without the operator's document being touched.
    #[test]
    fn an_address_override_reaches_the_node_and_leaves_the_inbound_alone() {
        let nodes = super::nodes(
            &document(),
            "server",
            &access_with_address(),
            "alice",
            Ok(&host()),
        );

        assert!(
            nodes[0]
                .as_ref()
                .unwrap()
                .endpoint
                .host
                .to_string()
                .eq("proxy.example.com"),
            "an inbound without an override still uses the public host"
        );
        assert_eq!(nodes[0].as_ref().unwrap().endpoint.port.to_string(), "443");
        assert_eq!(
            nodes[1].as_ref().unwrap().endpoint.host.to_string(),
            "cdn.example.com"
        );
        assert_eq!(nodes[1].as_ref().unwrap().endpoint.port.to_string(), "8444");

        let injected = inject(&document(), "server", &access_with_address()).unwrap();
        let inbounds = exports(
            &document(),
            "server",
            &access_with_address(),
            Ok(&host()),
            &Serving::Running(&injected),
        );
        assert!(inbounds[1].managed[0]
            .export
            .link
            .as_deref()
            .unwrap()
            .contains("@cdn.example.com:8444"));
        assert_eq!(inbounds[1].index, 1, "the document keeps its own inbound");
    }

    /// An address without a port keeps the inbound's own, and a port alone
    /// reuses the host it would otherwise inherit.
    #[test]
    fn either_half_of_an_override_stands_on_its_own() {
        for (endpoint, expected_host, port) in [
            (
                Endpoint {
                    address: Some("cdn.example.com".to_string()),
                    port: None,
                },
                "cdn.example.com",
                "8443",
            ),
            (
                Endpoint {
                    address: None,
                    port: Some(443),
                },
                "proxy.example.com",
                "443",
            ),
        ] {
            let mut access = access();
            access.endpoints.insert(
                "server".to_string(),
                BTreeMap::from([("trojan-in".to_string(), endpoint)]),
            );
            let nodes = super::nodes(&document(), "server", &access, "alice", Ok(&host()));

            assert_eq!(
                nodes[1].as_ref().unwrap().endpoint.host.to_string(),
                expected_host
            );
            assert_eq!(nodes[1].as_ref().unwrap().endpoint.port.to_string(), port);
        }
    }

    /// A stored address that is not a host is refused with its own reason
    /// rather than silently falling back to the public host.
    #[test]
    fn an_unparseable_stored_address_is_refused() {
        let mut access = access();
        access.endpoints.insert(
            "server".to_string(),
            BTreeMap::from([(
                "trojan-in".to_string(),
                Endpoint {
                    address: Some("not a host".to_string()),
                    port: None,
                },
            )]),
        );
        let nodes = super::nodes(&document(), "server", &access, "alice", Ok(&host()));

        assert_eq!(
            nodes[1].as_ref().unwrap_err().as_str(),
            "address: the stored address is not a host name or IP address"
        );
    }

    /// An entry that reaches no inbound, or one that cannot take users, has a
    /// reason to show beside its address.
    #[test]
    fn an_inbound_that_cannot_be_addressed_says_why() {
        let unknown = super::placement(&document(), &entry("server", "gone"));
        assert_eq!(unknown.reason(), Some("no inbound has this tag"));
        assert!(matches!(unknown, Placement::Unknown));

        let refused = super::placement(&document(), &entry("server", "direct-in"));
        assert!(refused.reason().is_some());
        assert!(matches!(refused, Placement::Refused(_)));

        let placed = super::placement(&document(), &entry("server", "trojan-in"));
        assert_eq!(placed.reason(), None);
        assert!(matches!(placed, Placement::Placed));
    }
}

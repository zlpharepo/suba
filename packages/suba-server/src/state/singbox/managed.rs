//! Managed users in the configuration the core runs, and the status of shared
//! bindings that leave the native document untouched.
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
use suba_core::proto::protocol::shadowtls;
use suba_core::proto::{
    write_link, Client, Endpoint as NodeEndpoint, Host, Name, Node, Outbound, RawParams, Secret,
    TlsClient, Transport,
};
use suba_singbox::users::{self, Protocol};

use crate::error::Error;
use crate::state::access::{Access, Entry, GrantMode};

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
        let at = Entry::local(config, tag);
        let planned: Vec<PlannedUser> = grants
            .iter()
            // Another instance's inbound is not an inbound of this document, so
            // it injects nothing here however it was granted.
            // `at` names a local inbound, and a hosted entry is never equal to
            // it, so another instance's inbound injects nothing here.
            .filter(|grant| {
                (grant.entry.same_inbound(&at) && grant.entry.mode == GrantMode::Managed)
                    || (grant.entry.host.is_none()
                        && grant.entry.config == config
                        && access
                            .endpoint(&grant.entry)
                            .and_then(|endpoint| endpoint.inner_inbound.as_deref())
                            == Some(tag)
                        && matches!(placement(document, &grant.entry), Placement::Placed)
                        && validate_inner(document, &grant.entry.inbound, tag).is_ok())
            })
            .filter_map(|grant| {
                let material = access.material(&grant.user, &at)?;
                Some(PlannedUser {
                    name: grant.user.clone(),
                    entry: users::user(protocol, inbound, &grant.user, &material)?,
                })
            })
            .fold(BTreeMap::new(), |mut users, planned| {
                users.insert(planned.name.clone(), planned);
                users
            })
            .into_values()
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

/// How far a managed credential or shared inbound configuration has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    /// The node's runtime could not be verified.
    Unknown,
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
    /// Distribution-only bindings; no native user is added for these.
    pub shared: Vec<Shared>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_refused: Option<&'static str>,
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

#[derive(Debug, Serialize)]
pub(crate) struct Shared {
    pub user: String,
    pub state: State,
    #[serde(flatten)]
    pub export: Export,
}

/// Hand-written users, managed users, and shared bindings of `config`.
pub(crate) fn exports(
    document: &Value,
    config: &str,
    access: &Access,
    host: Result<&Host, &str>,
    serving: &Serving<'_>,
) -> Vec<InboundUsers> {
    let plan = plan(document, config, access);
    let grants = access.grants();

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
                            export: if inbound.get("type").and_then(Value::as_str)
                                == Some("shadowtls")
                            {
                                composite_export(
                                    document,
                                    config,
                                    access,
                                    &plan,
                                    &user.name,
                                    &Entry::local(config, tag.unwrap_or_default()),
                                    host,
                                )
                            } else {
                                export(
                                    address_of(inbound, tag, config, access, host),
                                    &user.entry,
                                    "users",
                                    tag.unwrap_or_default(),
                                )
                            },
                        })
                        .collect()
                })
                .unwrap_or_default();
            let shared = if users::shareable(inbound).is_ok() {
                grants
                    .iter()
                    .filter(|grant| {
                        grant.entry.mode == GrantMode::Shared
                            && grant
                                .entry
                                .same_inbound(&Entry::local(config, tag.unwrap_or_default()))
                    })
                    .map(|grant| Shared {
                        user: grant.user.clone(),
                        state: shared_state(serving, tag, inbound),
                        export: if inbound.get("type").and_then(Value::as_str) == Some("shadowtls")
                        {
                            composite_export(
                                document,
                                config,
                                access,
                                &plan,
                                &grant.user,
                                &grant.entry,
                                host,
                            )
                        } else {
                            shared_export(
                                address_of(inbound, tag, config, access, host),
                                tag.unwrap_or_default(),
                            )
                        },
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let departing = departing(serving, tag, written, &managed);

            InboundUsers {
                index,
                tag: tag.map(str::to_owned),
                refused: users::grantable(inbound).err(),
                flow: users::flow(inbound),
                users,
                managed,
                shared,
                shared_refused: users::shareable(inbound).err(),
                departing,
            }
        })
        .collect()
}

/// The client nodes of one user in `config`, or why an entry has none yet.
pub(crate) fn nodes(
    document: &Value,
    config: &str,
    access: &Access,
    user: &str,
    host: Result<&Host, &str>,
) -> Vec<Result<Node<Client>, String>> {
    let plan = plan(document, config, access);
    let grants: Vec<_> = access
        .users
        .get(user)
        .into_iter()
        .flat_map(|held| access.grants_of(user, held))
        .filter(|grant| grant.entry.config == config && grant.entry.host.is_none())
        .collect();
    let inner_tags: BTreeSet<&str> = grants
        .iter()
        .filter_map(|grant| {
            let inner = access.endpoint(&grant.entry)?.inner_inbound.as_deref()?;
            (matches!(placement(document, &grant.entry), Placement::Placed)
                && validate_inner(document, &grant.entry.inbound, inner).is_ok())
            .then_some(inner)
        })
        .collect();

    let mut nodes: Vec<_> = plan
        .inbounds
        .iter()
        .filter_map(|(index, planned)| {
            let managed = planned.users.iter().find(|held| held.name == user)?;
            let inbound = &inbounds(document)[*index];
            let tag = inbound
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if inner_tags.contains(tag) {
                return None;
            }
            let at = Entry::local(config, tag);
            if inbound.get("type").and_then(Value::as_str) == Some("shadowtls") {
                return Some(composite(document, config, access, &plan, user, &at, host));
            }
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
        .collect();
    nodes.extend(
        grants
            .iter()
            .filter(|grant| {
                grant.entry.mode == GrantMode::Shared
                    && !inner_tags.contains(grant.entry.inbound.as_str())
            })
            .map(|grant| {
                let inbound = inbounds(document).iter().find(|inbound| {
                    inbound.get("tag").and_then(Value::as_str) == Some(&grant.entry.inbound)
                });
                let Some(inbound) = inbound else {
                    return Err("inbound: no inbound has this tag".to_string());
                };
                if inbound.get("type").and_then(Value::as_str) == Some("shadowtls") {
                    return composite(document, config, access, &plan, user, &grant.entry, host);
                }
                let dialable = address(inbound, access.endpoint(&grant.entry), host)?;
                users::shared_client(dialable.inbound(), &dialable.host, &grant.entry.inbound)
                    .map_err(|refused| refused.to_string())
            }),
    );
    nodes
}

fn composite(
    document: &Value,
    config: &str,
    access: &Access,
    plan: &Plan,
    user: &str,
    outer: &Entry,
    public: Result<&Host, &str>,
) -> Result<Node<Client>, String> {
    if !matches!(placement(document, outer), Placement::Placed) {
        return Err("inbound: this access mode is unavailable".to_string());
    }
    let inner_tag = access
        .endpoint(outer)
        .and_then(|endpoint| endpoint.inner_inbound.as_deref())
        .ok_or("inner_inbound: select an inner inbound".to_string())?;
    validate_inner(document, &outer.inbound, inner_tag)
        .map_err(|_| "inner_inbound: the selected inner inbound is unavailable".to_string())?;
    let outer_inbound = inbounds(document)
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(&outer.inbound))
        .ok_or("inbound: no inbound has this tag".to_string())?;
    let inner_index = inbounds(document)
        .iter()
        .position(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(inner_tag))
        .ok_or("inner_inbound: no inbound has this tag".to_string())?;
    let inner_inbound = &inbounds(document)[inner_index];
    let inner_at = Entry::local(config, inner_tag);
    let inner_address = address(inner_inbound, access.endpoint(&inner_at), public)?;
    let inner = if let Some(planned) = plan
        .inbounds
        .get(&inner_index)
        .and_then(|planned| planned.users.iter().find(|held| held.name == user))
    {
        users::client(
            inner_address.inbound(),
            &planned.entry,
            "users",
            &inner_address.host,
            inner_tag,
        )
    } else {
        users::shared_client(inner_address.inbound(), &inner_address.host, inner_tag)
    }
    .map_err(|refused| refused.to_string())?;
    if !matches!(inner.transport, Transport::Tcp) {
        return Err("inner_inbound.transport: ShadowTLS carries TCP only".to_string());
    }
    let outer_address = address(outer_inbound, access.endpoint(outer), public)?;
    let sni = outer_inbound
        .get("handshake")
        .and_then(|handshake| handshake.get("server"))
        .and_then(Value::as_str)
        .and_then(|value| Host::parse(value).ok())
        .ok_or("handshake.server: a TLS server name is needed".to_string())?;
    let version = outer_inbound
        .get("version")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let password = match version {
        1 => None,
        2 => Some(
            outer_inbound
                .get("password")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or("password: a shared ShadowTLS password is needed".to_string())?,
        ),
        3 => Some(
            plan.inbounds
                .iter()
                .find_map(|(index, planned)| {
                    (inbounds(document)[*index]
                        .get("tag")
                        .and_then(Value::as_str)
                        == Some(&outer.inbound))
                    .then(|| {
                        planned
                            .users
                            .iter()
                            .find(|held| held.name == user)
                            .and_then(|held| held.entry.get("password"))
                            .and_then(Value::as_str)
                    })
                    .flatten()
                })
                .ok_or("users.password: a managed ShadowTLS password is needed".to_string())?,
        ),
        _ => return Err("version: ShadowTLS version 1, 2, or 3 is needed".to_string()),
    };
    let tls = TlsClient {
        server_name: Some(sni),
        ..TlsClient::default()
    };
    Ok(Node {
        name: Name::from(outer.inbound.as_str()),
        endpoint: NodeEndpoint::new(
            outer_address.host.clone(),
            outer_address
                .inbound()
                .get("listen_port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .and_then(suba_core::proto::Port::new)
                .ok_or("listen_port: a port clients can dial is needed".to_string())?,
        ),
        listen: (),
        transport: Transport::Tcp,
        tls: Some(tls),
        protocol: Outbound::ShadowTls(shadowtls::Client {
            version: version as u8,
            password: password.map(|value| Secret::new(Box::from(value))),
            inner: Box::new(inner),
        }),
        extra: RawParams::new(),
    })
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

pub(crate) fn modes(inbound: &Value) -> Vec<GrantMode> {
    let mut modes = Vec::new();
    if users::grantable(inbound).is_ok() {
        modes.push(GrantMode::Managed);
    }
    if users::shareable(inbound).is_ok() {
        modes.push(GrantMode::Shared);
    }
    modes
}

/// A ShadowTLS relationship is explicit and stays inside one configuration.
pub(crate) fn validate_inner(document: &Value, outer: &str, inner: &str) -> Result<(), Error> {
    let inbounds = inbounds(document);
    let outer_inbound = inbounds
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(outer));
    if outer_inbound.and_then(|inbound| inbound.get("type").and_then(Value::as_str))
        != Some("shadowtls")
    {
        return Err(Error::Document(
            "inner_inbound: only ShadowTLS carries an inner inbound".to_string(),
        ));
    }
    if outer == inner {
        return Err(Error::Document(
            "inner_inbound: an inbound cannot carry itself".to_string(),
        ));
    }
    let Some(inner_inbound) = inbounds
        .iter()
        .find(|inbound| inbound.get("tag").and_then(Value::as_str) == Some(inner))
    else {
        return Err(Error::Document(
            "inner_inbound: no inbound has this tag".to_string(),
        ));
    };
    if inner_inbound.get("type").and_then(Value::as_str) == Some("shadowtls") {
        return Err(Error::Document(
            "inner_inbound: nested ShadowTLS is unsupported".to_string(),
        ));
    }
    if matches!(
        inner_inbound.get("type").and_then(Value::as_str),
        Some("hysteria" | "hysteria2" | "tuic" | "anytls")
    ) || inner_inbound.get("network").and_then(Value::as_str) == Some("udp")
        || inner_inbound
            .get("transport")
            .and_then(|transport| transport.get("type"))
            .and_then(Value::as_str)
            == Some("quic")
    {
        return Err(Error::Document(
            "inner_inbound: ShadowTLS carries TCP only".to_string(),
        ));
    }
    if users::grantable(inner_inbound).is_err() && users::shareable(inner_inbound).is_err() {
        return Err(Error::Document(
            "inner_inbound: this inbound has no client credential".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn shared_warning(inbound: &Value) -> Option<&'static str> {
    match inbound.get("type").and_then(Value::as_str) {
        Some("shadowtls")
            if matches!(
                inbound.get("version").and_then(Value::as_u64),
                None | Some(0 | 1)
            ) =>
        {
            Some("ShadowTLS v1 has no outer authentication")
        }
        Some("snell")
            if inbound.get("version").and_then(Value::as_u64) == Some(6)
                && inbound.get("mode").and_then(Value::as_str) == Some("unsafe-raw") =>
        {
            Some("Snell v6 unsafe-raw does not authenticate the PSK")
        }
        _ => None,
    }
}

pub(crate) fn managed_warning(inbound: &Value) -> Option<&'static str> {
    (inbound.get("type").and_then(Value::as_str) == Some("snell"))
        .then_some("Surge cannot use Snell user keys")
}

pub(crate) fn shared_refusal(inbound: &Value) -> Option<&'static str> {
    (inbound.get("type").and_then(Value::as_str) == Some("snell"))
        .then(|| users::shareable(inbound).err())
        .flatten()
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
        Some(inbound) => match match entry.mode {
            GrantMode::Managed => users::grantable(inbound).map(|_| ()),
            GrantMode::Shared => users::shareable(inbound),
        } {
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

fn shared_export(dialable: Result<Dialable<'_>, String>, name: &str) -> Export {
    let dialable = match dialable {
        Ok(dialable) => dialable,
        Err(reason) => return refusal(reason),
    };
    match users::shared_client(dialable.inbound(), &dialable.host, name) {
        Err(refused) => refusal(refused.to_string()),
        Ok(node) => Export {
            link: write_link(&node).ok(),
            outbound: outbound(name, &node),
            reason: None,
        },
    }
}

fn composite_export(
    document: &Value,
    config: &str,
    access: &Access,
    plan: &Plan,
    user: &str,
    outer: &Entry,
    host: Result<&Host, &str>,
) -> Export {
    match composite(document, config, access, plan, user, outer, host) {
        Err(reason) => refusal(reason),
        Ok(node) => Export {
            link: None,
            outbound: outbound(&outer.inbound, &node),
            reason: None,
        },
    }
}

#[cfg(feature = "singbox")]
fn outbound(tag: &str, node: &Node<Client>) -> Option<Value> {
    if matches!(node.protocol, Outbound::ShadowTls(_)) {
        let (values, refused) = suba_singbox::outbounds(&[(tag, node)]);
        return refused
            .is_empty()
            .then(|| serde_json::json!({ "outbounds": values }));
    }
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
    let at = Entry::local(config, tag.unwrap_or_default());
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

fn shared_state(serving: &Serving<'_>, tag: Option<&str>, inbound: &Value) -> State {
    match serving {
        Serving::Not { in_use: true } => State::Stopped,
        Serving::Not { in_use: false } => State::Unused,
        Serving::Running(product) => {
            let applied = inbounds(product)
                .iter()
                .find(|held| tag.is_some() && held.get("tag").and_then(Value::as_str) == tag);
            if applied == Some(inbound) {
                State::Applied
            } else {
                State::Pending
            }
        }
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
    use uuid::Uuid;

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
        Entry::local(config, inbound)
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
                    ..Endpoint::default()
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
    fn shadowtls_binding_injects_inner_user_and_delivers_only_composite() {
        let document = json!({"inbounds": [
            {"type": "shadowtls", "tag": "outer", "version": 3, "listen_port": 443,
             "handshake": {"server": "cover.example.com", "server_port": 443}},
            {"type": "trojan", "tag": "inner", "listen_port": 8443,
             "tls": {"enabled": true}}
        ]});
        let mut access = Access::default();
        access.users.insert(
            "alice".into(),
            User {
                inbounds: vec![entry("server", "outer")],
                secret: "11".repeat(32),
                ..User::default()
            },
        );
        access.endpoints.insert(
            "server".into(),
            BTreeMap::from([(
                "outer".into(),
                Endpoint {
                    inner_inbound: Some("inner".into()),
                    ..Endpoint::default()
                },
            )]),
        );

        let product = inject(&document, "server", &access).unwrap();
        assert_eq!(names(&product, 0), ["alice"]);
        assert_eq!(names(&product, 1), ["alice"]);
        let nodes = nodes(&document, "server", &access, "alice", Ok(&host()));
        assert_eq!(nodes.len(), 1);
        let node = nodes[0].as_ref().unwrap();
        assert!(matches!(
            node.protocol,
            suba_core::proto::Outbound::ShadowTls(_)
        ));
    }

    #[test]
    fn shared_shadowtls_authorizes_its_inner_shadowsocks_user() {
        let document = json!({"inbounds": [
            {"type": "shadowtls", "tag": "outer", "version": 2, "password": "outer-key",
             "listen_port": 443, "handshake": {"server": "cover.example.com", "server_port": 443}},
            {"type": "shadowsocks", "tag": "inner", "listen_port": 8443,
             "method": "aes-256-gcm", "password": "inner-key"}
        ]});
        let mut access = Access::default();
        access.users.insert(
            "alice".into(),
            User {
                inbounds: vec![Entry {
                    mode: GrantMode::Shared,
                    ..entry("server", "outer")
                }],
                secret: "11".repeat(32),
                ..User::default()
            },
        );
        access.endpoints.insert(
            "server".into(),
            BTreeMap::from([(
                "outer".into(),
                Endpoint {
                    inner_inbound: Some("inner".into()),
                    ..Endpoint::default()
                },
            )]),
        );

        let product = inject(&document, "server", &access).unwrap();
        assert_eq!(names(&product, 1), ["alice"]);
        let nodes = nodes(&document, "server", &access, "alice", Ok(&host()));
        assert_eq!(nodes.len(), 1);
        let node = nodes[0].as_ref().unwrap();
        let Outbound::ShadowTls(client) = &node.protocol else {
            panic!("a composite node is needed")
        };
        assert_eq!(client.password.as_ref().unwrap().as_str(), "outer-key");
        assert!(matches!(client.inner.protocol, Outbound::Shadowsocks(_)));
        let preview = exports(
            &document,
            "server",
            &access,
            Ok(&host()),
            &Serving::Not { in_use: false },
        );
        assert!(preview[0].shared[0].export.reason.is_none());
        #[cfg(feature = "singbox")]
        assert_eq!(
            preview[0].shared[0].export.outbound.as_ref().unwrap()["outbounds"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn shared_shadowtls_carries_single_credential_2022_chacha_without_injection() {
        let document = json!({"inbounds": [
            {"type": "shadowtls", "tag": "outer", "version": 2, "password": "outer-key",
             "listen_port": 443, "handshake": {"server": "cover.example.com", "server_port": 443}},
            {"type": "shadowsocks", "tag": "inner", "listen_port": 8443,
             "method": "2022-blake3-chacha20-poly1305",
             "password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        ]});
        let mut access = Access::default();
        access.users.insert(
            "alice".into(),
            User {
                inbounds: vec![Entry {
                    mode: GrantMode::Shared,
                    ..entry("server", "outer")
                }],
                secret: "11".repeat(32),
                ..User::default()
            },
        );
        access.endpoints.insert(
            "server".into(),
            BTreeMap::from([(
                "outer".into(),
                Endpoint {
                    inner_inbound: Some("inner".into()),
                    ..Endpoint::default()
                },
            )]),
        );

        assert_eq!(inject(&document, "server", &access).unwrap(), document);
        let nodes = nodes(&document, "server", &access, "alice", Ok(&host()));
        assert_eq!(nodes.len(), 1);
        let Outbound::ShadowTls(client) = &nodes[0].as_ref().unwrap().protocol else {
            panic!("a composite node is needed")
        };
        let Outbound::Shadowsocks(inner) = &client.inner.protocol else {
            panic!("the inner Shadowsocks credential is needed")
        };
        assert_eq!(inner.method.as_ref(), "2022-blake3-chacha20-poly1305");
        assert_eq!(
            inner.password.as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn stale_outer_access_mode_cannot_authorize_inner_users() {
        let document = json!({"inbounds": [
            {"type": "shadowtls", "tag": "outer", "version": 3, "listen_port": 443},
            {"type": "trojan", "tag": "inner", "listen_port": 8443}
        ]});
        let mut access = Access::default();
        access.users.insert(
            "alice".into(),
            User {
                inbounds: vec![Entry {
                    mode: GrantMode::Shared,
                    ..entry("server", "outer")
                }],
                secret: "11".repeat(32),
                ..User::default()
            },
        );
        access.endpoints.insert(
            "server".into(),
            BTreeMap::from([(
                "outer".into(),
                Endpoint {
                    inner_inbound: Some("inner".into()),
                    ..Endpoint::default()
                },
            )]),
        );
        let product = inject(&document, "server", &access).unwrap();
        assert!(names(&product, 1).is_empty());
    }

    #[test]
    fn shared_credential_inbounds_export_without_injecting_users() {
        let document = json!({"inbounds": [
            {"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-chacha20-poly1305", "password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "listen_port": 1080},
            {"type": "snell", "tag": "snell", "version": 6, "psk": "shared-secret", "listen_port": 1081},
            {"type": "shadowtls", "tag": "shadow", "version": 2, "password": "key", "listen_port": 1082},
            {"type": "shadowtls", "tag": "legacy", "version": 1, "listen_port": 1083}
        ]});
        let mut access = Access::default();
        let inbounds = ["ss", "snell", "shadow", "legacy"]
            .into_iter()
            .map(|tag| Entry {
                mode: GrantMode::Shared,
                ..entry("server", tag)
            })
            .collect();
        access.users.insert(
            "alice".into(),
            User {
                inbounds,
                secret: "11".repeat(32),
                ..User::default()
            },
        );

        assert_eq!(inject(&document, "server", &access).unwrap(), document);
        assert_eq!(modes(&document["inbounds"][0]), [GrantMode::Shared]);
        assert_eq!(
            modes(&document["inbounds"][1]),
            [GrantMode::Managed, GrantMode::Shared]
        );
        assert_eq!(
            shared_warning(&document["inbounds"][3]),
            Some("ShadowTLS v1 has no outer authentication")
        );
        assert_eq!(
            shared_warning(&json!({"type": "snell", "version": 6, "mode": "unsafe-raw"})),
            Some("Snell v6 unsafe-raw does not authenticate the PSK")
        );
        let exports = exports(
            &document,
            "server",
            &access,
            Ok(&host()),
            &Serving::Running(&document),
        );
        for inbound in &exports {
            assert!(inbound.managed.is_empty());
            assert_eq!(inbound.shared.len(), 1);
            assert_eq!(inbound.shared[0].user, "alice");
            assert_eq!(inbound.shared[0].state, State::Applied);
        }
        assert!(exports[0].shared[0]
            .export
            .link
            .as_deref()
            .is_some_and(|link| link.starts_with("ss://")));
        #[cfg(feature = "singbox")]
        assert_eq!(
            exports[0].shared[0].export.outbound.as_ref().unwrap()["type"],
            "shadowsocks"
        );
        assert!(exports[0].shared[0].export.reason.is_none());
        assert!(exports[1].shared[0]
            .export
            .link
            .as_deref()
            .is_some_and(|link| link.starts_with("snell://")));
        assert!(exports[2..]
            .iter()
            .all(|inbound| inbound.shared[0].export.reason.is_some()));
        let nodes = nodes(&document, "server", &access, "alice", Ok(&host()));
        assert_eq!(nodes.len(), 4);
        assert!(nodes[0].is_ok());
        assert!(nodes[1].is_ok());
        assert!(nodes[2..].iter().all(Result::is_err));
        let managed_document = json!({"inbounds": [{"type": "snell", "tag": "snell", "version": 5, "psk": "shared-secret"}]});
        let mut managed_access = Access::default();
        managed_access.users.insert(
            "alice".into(),
            User {
                inbounds: vec![entry("server", "snell")],
                secret: "11".repeat(32),
                ..User::default()
            },
        );
        let injected = inject(&managed_document, "server", &managed_access).unwrap();
        assert_eq!(names(&injected, 0), ["alice"]);
        assert!(injected["inbounds"][0]["users"][0]["userkey"].is_string());

        let shared = Entry {
            mode: GrantMode::Shared,
            ..entry("server", "snell")
        };
        let mut with_native_users = managed_document;
        with_native_users["inbounds"][0]["users"] = json!([{"name": "native", "userkey": "key"}]);
        assert!(matches!(
            placement(&with_native_users, &shared),
            Placement::Refused(_)
        ));
        assert_eq!(
            shared_refusal(&with_native_users["inbounds"][0]),
            Some("Snell users require a user key, not a shared PSK alone")
        );
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

    /// Another instance's inbound shares this configuration's name and tag by
    /// construction, so its entry has to be told apart by the host that runs it.
    #[test]
    fn an_entry_of_another_host_is_not_an_inbound_of_this_document() {
        let mut access = access();
        let elsewhere = Uuid::now_v7();
        access.users.get_mut("alice").unwrap().inbounds = vec![
            entry("server", "vless-in"),
            Entry {
                host: Some(elsewhere),
                config: "server".to_string(),
                inbound: "vless-in".to_string(),
                mode: GrantMode::Managed,
            },
        ];

        let injected = inject(&document(), "server", &access).unwrap();

        assert_eq!(
            names(&injected, 0),
            ["guest", "alice"],
            "the same tag on another host is not this document's inbound,              and the local entry still is"
        );
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
                    ..Endpoint::default()
                },
                "cdn.example.com",
                "8443",
            ),
            (
                Endpoint {
                    address: None,
                    port: Some(443),
                    ..Endpoint::default()
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
                    ..Endpoint::default()
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

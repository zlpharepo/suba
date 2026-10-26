//! The read-only subset of sing-box's daemon API v4 wire contract.
//!
//! Field numbers follow `daemon/started_service.proto`; unknown protobuf fields
//! are ignored so unrelated native API additions do not widen this adapter.

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Empty {}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Version {
    #[prost(int32, tag = "2")]
    pub api_version: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Interval {
    #[prost(int64, tag = "1")]
    pub interval: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Status {
    #[prost(bool, tag = "5")]
    pub traffic_available: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Events {
    #[prost(message, repeated, tag = "1")]
    pub events: Vec<Event>,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Event {
    #[prost(int32, tag = "1")]
    pub kind: i32,
    #[prost(string, tag = "2")]
    pub id: String,
    #[prost(message, optional, tag = "3")]
    pub connection: Option<Connection>,
    #[prost(int64, tag = "4")]
    pub uplink_delta: i64,
    #[prost(int64, tag = "5")]
    pub downlink_delta: i64,
    #[prost(int64, tag = "6")]
    pub closed_at: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Connection {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub inbound: String,
    #[prost(string, tag = "5")]
    pub network: String,
    #[prost(string, tag = "6")]
    pub source: String,
    #[prost(string, tag = "7")]
    pub destination: String,
    #[prost(string, tag = "8")]
    pub domain: String,
    #[prost(string, tag = "10")]
    pub user: String,
    #[prost(int64, tag = "12")]
    pub created_at: i64,
    #[prost(int64, tag = "13")]
    pub closed_at: i64,
    #[prost(int64, tag = "16")]
    pub uplink_total: i64,
    #[prost(int64, tag = "17")]
    pub downlink_total: i64,
}

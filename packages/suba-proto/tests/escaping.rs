//! What the writer must never do: produce a link that means something else when it is read back.
//!
//! Every case below is a parse → write → parse. The value under test is always something a lenient
//! parser accepted and that carries a query delimiter, because that is the shape that turns one
//! parameter into two — or turns an SNI into an instruction to stop verifying certificates.

use suba_proto::percent::encode_into;
use suba_proto::{parse_link, write_link, Client, Node};

/// Encode a value the way a provider has to, so that it arrives as one parameter.
fn encoded(value: &str) -> String {
    let mut out = String::new();
    encode_into(value, &mut out);

    out
}

fn round_trip(link: &str) -> (Node<Client>, String) {
    let node = parse_link(link).unwrap_or_else(|error| panic!("{link}\n  {error}"));
    let written = write_link(&node).unwrap_or_else(|error| panic!("{link}\n  {error}"));
    let again = parse_link(&written).unwrap_or_else(|error| panic!("{written}\n  {error}"));

    assert_eq!(
        again, node,
        "the round trip changed the node\n  in: {link}\n out: {written}"
    );

    let twice = write_link(&again).unwrap();

    assert_eq!(
        twice, written,
        "writing twice is not writing once\n  {link}"
    );

    (node, written)
}

fn vless_with_sni(sni: &str) -> String {
    format!(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443\
         ?encryption=none&security=tls&sni={}&type=tcp#Probe",
        encoded(sni)
    )
}

#[test]
fn an_sni_cannot_smuggle_a_tls_setting() {
    // `insecure` and `allow_insecure` are spellings this reader accepts, and the host parser accepts
    // the delimiters that carry them: unescaped, `sni=good&insecure=1` reparses as an SNI of `good`
    // plus a flag that turns certificate verification off.
    for spelling in ["insecure", "allow_insecure"] {
        let (node, written) = round_trip(&vless_with_sni(&format!("good&{spelling}=1")));

        assert_eq!(
            node.tls.as_ref().map(|tls| tls.insecure),
            Some(false),
            "the link alone disabled verification"
        );
        assert!(
            !written.contains("sni=good&"),
            "the SNI reached the output unescaped: {written}"
        );
    }
}

#[test]
fn a_delimiter_inside_a_recognised_field_stays_there() {
    // Values a host parser accepts and a query parser would not. (A space, `#`, `?`, `/`, `:` or `@`
    // never gets this far: the host parser refuses them.)
    for value in [
        "a&b",
        "a=b",
        "a&b=c",
        "50%",
        "über.example",
        "plus+sign",
        "semi;colon",
        "comma,here",
    ] {
        let (node, _) = round_trip(&vless_with_sni(value));

        assert_eq!(
            node.tls
                .as_ref()
                .and_then(|tls| tls.server_name.as_ref())
                .map(ToString::to_string),
            Some(value.to_string()),
            "the SNI did not survive the round trip"
        );
    }
}

#[test]
fn an_unmodelled_key_with_a_delimiter_stays_one_parameter() {
    let link = format!(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443\
         ?encryption=none&type=tcp&{}=1#Probe",
        encoded("a&b")
    );
    let (node, written) = round_trip(&link);

    let keys: Vec<String> = node.extra.iter().map(|(key, _)| key.to_string()).collect();

    assert_eq!(keys, ["a&b"], "the key lost its delimiter");
    assert!(
        !written.contains("&a&b="),
        "the key reached the output unescaped: {written}"
    );
}

#[test]
fn a_userinfo_cannot_move_the_host() {
    // AnyTLS keeps its whole credential in the userinfo, and a password may contain `@`, `/` or `#`.
    let (node, written) = round_trip(&format!(
        "anytls://{}@example.com:443#Probe",
        encoded("p@ss/word#1")
    ));

    assert_eq!(node.endpoint.to_string(), "example.com:443");
    assert!(
        !written.contains("p@ss"),
        "the password reached the output unescaped: {written}"
    );

    // TUIC joins two fields with `:`: the separator survives, the halves are escaped.
    let (node, written) = round_trip(&format!(
        "tuic://11111111-1111-1111-1111-111111111111:{}@example.com:443#Probe",
        encoded("pw@d:pw")
    ));

    assert_eq!(node.endpoint.to_string(), "example.com:443");
    assert!(
        !written.contains("pw@d"),
        "the password reached the output unescaped: {written}"
    );
}

#[test]
fn an_alpn_list_is_written_as_one_value() {
    let link = "vless://11111111-1111-1111-1111-111111111111@example.com:443\
                ?encryption=none&security=tls&alpn=h2%2Chttp%2F1.1&type=tcp#Probe";
    let (node, written) = round_trip(link);

    let alpn: Vec<String> = node
        .tls
        .as_ref()
        .map(|tls| tls.alpn.iter().map(ToString::to_string).collect())
        .unwrap_or_default();

    assert_eq!(alpn, ["h2", "http/1.1"]);
    assert!(
        written.contains("alpn=h2%2Chttp%2F1.1"),
        "the ALPN list was not written as one escaped value: {written}"
    );
}

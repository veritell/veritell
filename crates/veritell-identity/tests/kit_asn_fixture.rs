//! The rollout kit's ASN fixture (`deploy/fixtures/ip2asn.tsv`) is what
//! `deploy/test_asn.sh` downloads and checks with `asn_check`: the gateway
//! must load the same file, so that the kit's check and the gateway's parser
//! agree on it.

use std::net::IpAddr;
use veritell_identity::{AsnDb, NetClass};

const FIXTURE: &str = include_str!("../../../deploy/fixtures/ip2asn.tsv");

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn the_kit_fixture_loads() {
    let db = AsnDb::from_iptoasn_tsv(FIXTURE).expect("the kit's fixture loads");
    // Six rows, one of them unrouted (AS 0).
    assert_eq!(db.len(), 5);
}

#[test]
fn the_kit_fixture_classifies() {
    let db = AsnDb::from_iptoasn_tsv(FIXTURE).unwrap();
    let cloud = db.lookup(ip("192.0.2.7")).unwrap();
    assert_eq!((cloud.asn, cloud.class), (16509, NetClass::Hosting));
    assert_eq!(cloud.detection().unwrap().id, "net_hosting");
    let home = db.lookup(ip("198.51.100.7")).unwrap();
    assert_eq!((home.asn, home.class), (64500, NetClass::Other));
    assert!(home.detection().is_none());
    assert_eq!(db.lookup(ip("2001:db8::1")).unwrap().asn, 64502);
    assert!(db.lookup(ip("1.0.2.1")).is_none(), "unrouted");
    assert!(db.lookup(ip("10.0.0.1")).is_none(), "not in the file");
}

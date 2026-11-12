//! Tests for the address-fallback behaviour of `fetch_with`.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use veritell_directory::{fetch_with, DirectoryUrl, FetchConfig, FetchError, Response, Transport};

struct Multi {
    addrs: Vec<IpAddr>,
    /// Per address: Err = unreachable, Ok(status) = answered.
    outcome: Vec<(IpAddr, Result<u16, String>)>,
    gets: RefCell<Vec<SocketAddr>>,
}

const BODY: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;

impl Transport for Multi {
    fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, String> {
        Ok(self.addrs.clone())
    }
    fn get(&self, addr: SocketAddr, _: &DirectoryUrl, _: usize, _: Duration) -> Result<Response, String> {
        self.gets.borrow_mut().push(addr);
        let (_, r) = self.outcome.iter().find(|(ip, _)| *ip == addr.ip()).expect("unexpected address");
        match r {
            Err(e) => Err(e.clone()),
            Ok(status) => Ok(Response { status: *status, cache_control: None, body: BODY.as_bytes().to_vec() }),
        }
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn url() -> DirectoryUrl {
    veritell_directory::parse_url("https://agent.example/k").unwrap()
}

fn multi(outcome: &[(&str, Result<u16, &str>)]) -> Multi {
    Multi {
        addrs: outcome.iter().map(|(a, _)| ip(a)).collect(),
        outcome: outcome.iter().map(|(a, r)| (ip(a), (*r).map_err(str::to_string))).collect(),
        gets: RefCell::new(Vec::new()),
    }
}

#[test]
fn next_address_is_tried_after_a_transport_failure() {
    let t = multi(&[("93.184.216.34", Err("connection refused")), ("1.1.1.1", Ok(200))]);
    let r = fetch_with(&t, &url(), &FetchConfig::default());
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(t.gets.borrow().len(), 2);
    assert_eq!(t.gets.borrow()[1].ip(), ip("1.1.1.1"));
}

#[test]
fn an_http_answer_ends_the_attempts() {
    let t = multi(&[("93.184.216.34", Ok(503)), ("1.1.1.1", Ok(200))]);
    assert_eq!(fetch_with(&t, &url(), &FetchConfig::default()), Err(FetchError::Status(503)));
    assert_eq!(t.gets.borrow().len(), 1);
}

#[test]
fn all_addresses_failing_gives_the_last_transport_error() {
    let t = multi(&[("93.184.216.34", Err("first")), ("1.1.1.1", Err("second"))]);
    assert_eq!(
        fetch_with(&t, &url(), &FetchConfig::default()),
        Err(FetchError::Transport("second".to_string()))
    );
    assert_eq!(t.gets.borrow().len(), 2);
}

#[test]
fn a_refused_address_is_never_connected_to() {
    let t = multi(&[("93.184.216.34", Err("down")), ("192.88.99.1", Ok(200))]);
    assert_eq!(
        fetch_with(&t, &url(), &FetchConfig::default()),
        Err(FetchError::AddressRefused(ip("192.88.99.1")))
    );
    assert!(t.gets.borrow().is_empty());
}

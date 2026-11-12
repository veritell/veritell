//! A small RFC 8941 structured-field parser, limited to what Web Bot Auth
//! needs: dictionaries whose members are items or inner lists, with
//! parameters. Everything is strict: any deviation yields `None`, and
//! duplicate dictionary keys or parameter keys are rejected rather than
//! resolved "last wins", so two parsers can never disagree about which value
//! was signed.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;

/// Standard-alphabet base64 that tolerates missing padding.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Bare {
    Int(i64),
    Decimal,
    Str(String),
    Token(String),
    Bytes(Vec<u8>),
    Bool(bool),
}

pub(crate) type Params = Vec<(String, Bare)>;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Item {
    pub bare: Bare,
    pub params: Params,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    List { items: Vec<Item>, params: Params },
    Item(Item),
}

impl Value {
    pub(crate) fn params(&self) -> &Params {
        match self {
            Value::List { params, .. } => params,
            Value::Item(item) => &item.params,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Member<'a> {
    pub key: String,
    pub value: Value,
    /// The member's value text exactly as it appeared (after `=`).
    pub text: &'a str,
}

pub(crate) fn param<'a>(params: &'a Params, name: &str) -> Option<&'a Bare> {
    params.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

struct Cursor<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Cursor { src, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn eat(&mut self, want: u8) -> bool {
        if self.peek() == Some(want) {
            self.pos = self.pos.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a str {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if f(b) {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
        // Only ASCII bytes are consumed here, so both ends are boundaries.
        self.src.get(start..self.pos).unwrap_or("")
    }

    fn key(&mut self) -> Option<String> {
        match self.peek() {
            Some(b) if b.is_ascii_lowercase() || b == b'*' => {}
            _ => return None,
        }
        let k = self.take_while(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*')
        });
        Some(k.to_string())
    }

    fn params(&mut self) -> Option<Params> {
        let mut out: Params = Vec::new();
        while self.peek() == Some(b';') {
            self.pos = self.pos.saturating_add(1);
            self.skip_sp();
            let k = self.key()?;
            let v = if self.eat(b'=') {
                self.bare()?
            } else {
                Bare::Bool(true)
            };
            if out.iter().any(|(existing, _)| *existing == k) {
                return None;
            }
            out.push((k, v));
        }
        Some(out)
    }

    fn bare(&mut self) -> Option<Bare> {
        match self.peek()? {
            b'"' => self.string(),
            b':' => self.bytes(),
            b'?' => self.boolean(),
            b'-' | b'0'..=b'9' => self.number(),
            b if b.is_ascii_alphabetic() || b == b'*' => self.token(),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<Bare> {
        self.bump()?; // opening quote
        let mut s = String::new();
        loop {
            match self.bump()? {
                b'\\' => match self.bump()? {
                    b @ (b'"' | b'\\') => s.push(char::from(b)),
                    _ => return None,
                },
                b'"' => return Some(Bare::Str(s)),
                b @ 0x20..=0x7e => s.push(char::from(b)),
                _ => return None,
            }
        }
    }

    fn token(&mut self) -> Option<Bare> {
        let t = self.take_while(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                        | b':'
                        | b'/'
                )
        });
        Some(Bare::Token(t.to_string()))
    }

    fn bytes(&mut self) -> Option<Bare> {
        self.bump()?; // opening colon
        let body = self.take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if !self.eat(b':') {
            return None;
        }
        LENIENT.decode(body).ok().map(Bare::Bytes)
    }

    fn boolean(&mut self) -> Option<Bare> {
        self.bump()?; // '?'
        match self.bump()? {
            b'1' => Some(Bare::Bool(true)),
            b'0' => Some(Bare::Bool(false)),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<Bare> {
        let negative = self.eat(b'-');
        let int_part = self.take_while(|b| b.is_ascii_digit());
        if int_part.is_empty() {
            return None;
        }
        if self.eat(b'.') {
            let frac = self.take_while(|b| b.is_ascii_digit());
            if int_part.len() > 12 || frac.is_empty() || frac.len() > 3 {
                return None;
            }
            return Some(Bare::Decimal);
        }
        if int_part.len() > 15 {
            return None;
        }
        let mut v: i64 = 0;
        for b in int_part.bytes() {
            let d = i64::from(b.checked_sub(b'0')?);
            v = v.checked_mul(10)?.checked_add(d)?;
        }
        Some(Bare::Int(if negative { v.checked_neg()? } else { v }))
    }

    fn item(&mut self) -> Option<Item> {
        let bare = self.bare()?;
        let params = self.params()?;
        Some(Item { bare, params })
    }

    fn value(&mut self) -> Option<Value> {
        if self.peek() == Some(b'(') {
            self.pos = self.pos.saturating_add(1);
            let mut items = Vec::new();
            loop {
                self.skip_sp();
                if self.eat(b')') {
                    let params = self.params()?;
                    return Some(Value::List { items, params });
                }
                items.push(self.item()?);
                if !matches!(self.peek(), Some(b' ') | Some(b')')) {
                    return None;
                }
            }
        }
        self.item().map(Value::Item)
    }
}

fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// Parses a dictionary. `None` means the field is invalid.
pub(crate) fn parse_dictionary(src: &str) -> Option<Vec<Member<'_>>> {
    let src = trim_ows(src);
    let mut c = Cursor::new(src);
    let mut out: Vec<Member<'_>> = Vec::new();
    if c.at_end() {
        return Some(out);
    }
    loop {
        let key = c.key()?;
        let start;
        let value;
        if c.eat(b'=') {
            start = c.pos;
            value = c.value()?;
        } else {
            start = c.pos;
            let params = c.params()?;
            value = Value::Item(Item {
                bare: Bare::Bool(true),
                params,
            });
        }
        let text = src.get(start..c.pos)?;
        if out.iter().any(|m| m.key == key) {
            return None;
        }
        out.push(Member { key, value, text });
        c.skip_ows();
        if c.at_end() {
            return Some(out);
        }
        if !c.eat(b',') {
            return None;
        }
        c.skip_ows();
        if c.at_end() {
            return None;
        }
    }
}

/// Parses one dictionary member value (the text after `label=`) that must be
/// an inner list. The whole input (trimmed) must be consumed.
pub(crate) fn parse_inner_list(member: &str) -> Option<(Vec<Item>, Params)> {
    let mut c = Cursor::new(trim_ows(member));
    let v = c.value()?;
    if !c.at_end() {
        return None;
    }
    match v {
        Value::List { items, params } => Some((items, params)),
        Value::Item(_) => None,
    }
}

/// Parses a whole field value (trimmed) that must be one item with its
/// parameters, for example `"https://agent.example"`.
pub(crate) fn parse_item(src: &str) -> Option<Item> {
    let mut c = Cursor::new(trim_ows(src));
    let item = c.item()?;
    if c.at_end() {
        Some(item)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Bare {
        Bare::Str(v.to_string())
    }

    #[test]
    fn empty_and_whitespace_dictionaries() {
        assert!(parse_dictionary("").unwrap().is_empty());
        assert!(parse_dictionary("  \t ").unwrap().is_empty());
    }

    #[test]
    fn commas_inside_strings_lists_and_bytes_do_not_split() {
        let d = parse_dictionary(
            "a=(\"x, y\" \"z\");k=\"1,2\", b=:QUJD:, c=\"q\\\",r\\\\\", d=?1",
        )
        .unwrap();
        let keys: Vec<&str> = d.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, ["a", "b", "c", "d"]);
        match &d[0].value {
            Value::List { items, params } => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].bare, s("x, y"));
                assert_eq!(param(params, "k"), Some(&s("1,2")));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(d[0].text, "(\"x, y\" \"z\");k=\"1,2\"");
        assert!(matches!(&d[1].value, Value::Item(Item { bare: Bare::Bytes(b), .. }) if b == b"ABC"));
        assert!(matches!(&d[2].value, Value::Item(Item { bare: Bare::Str(v), .. }) if v == "q\",r\\"));
    }

    #[test]
    fn parameters_of_every_kind() {
        let d = parse_dictionary("a=(\"h\");i=-5;s=\"v\";t=tok/en:x;b;f=?0;d=1.25").unwrap();
        let p = d[0].value.params();
        assert_eq!(param(p, "i"), Some(&Bare::Int(-5)));
        assert_eq!(param(p, "s"), Some(&s("v")));
        assert_eq!(param(p, "t"), Some(&Bare::Token("tok/en:x".into())));
        assert_eq!(param(p, "b"), Some(&Bare::Bool(true)));
        assert_eq!(param(p, "f"), Some(&Bare::Bool(false)));
        assert_eq!(param(p, "d"), Some(&Bare::Decimal));
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "=",
            "a=",
            "a=(",
            "a=((",
            "a=(\"x\"",
            "a=(\"x\"\"y\")",
            "a=\"unterminated",
            "a=\"bad\\n\"",
            "a=\"\u{e9}\"",
            "a=\"tab\there\"",
            "A=1",
            "\u{e9}=1",
            "a=1,",
            "a=1,,b=2",
            "a=1 b=2",
            "a=1, a=2",
            "a=1;p=1;p=2",
            "a=1234567890123456",
            "a=99999999999999999999999",
            "a=1.",
            "a=1.2345",
            "a=-",
            "a=:!!:",
            "a=:QUJD",
            "a=?2",
            ",",
        ] {
            assert!(parse_dictionary(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn integer_limits() {
        let d = parse_dictionary("a=999999999999999;b=-999999999999999").unwrap();
        assert_eq!(d[0].value, Value::Item(Item {
            bare: Bare::Int(999_999_999_999_999),
            params: vec![("b".into(), Bare::Int(-999_999_999_999_999))],
        }));
    }

    #[test]
    fn inner_list_text_is_preserved_and_must_be_whole() {
        let (items, params) = parse_inner_list(" (\"a\" \"b\");x=1 ").unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(params.len(), 1);
        assert!(parse_inner_list("(\"a\") junk").is_none());
        assert!(parse_inner_list("\"a\"").is_none());
        assert!(parse_inner_list("()").is_some());
    }

    #[test]
    fn missing_padding_is_tolerated_in_byte_sequences() {
        let d = parse_dictionary("a=:QUI:").unwrap();
        assert!(matches!(&d[0].value, Value::Item(Item { bare: Bare::Bytes(b), .. }) if b == b"AB"));
    }

    #[test]
    fn never_panics_on_arbitrary_text() {
        let alphabet: Vec<char> = "a=(\"\\ ,;:?-.1\u{e9}\u{0}x*".chars().collect();
        // Deterministic exhaustive walk over short strings.
        let mut stack = vec![String::new()];
        while let Some(cur) = stack.pop() {
            let _ = parse_dictionary(&cur);
            let _ = parse_inner_list(&cur);
            if cur.chars().count() < 4 {
                for ch in &alphabet {
                    let mut next = cur.clone();
                    next.push(*ch);
                    stack.push(next);
                }
            }
        }
    }

    #[test]
    fn member_text_excludes_whitespace_around_commas() {
        let d = parse_dictionary("a=1, b=tok,  c=\"str\" , d=?1 ,e=(\"x\" );p=2 , f").unwrap();
        let texts: Vec<&str> = d.iter().map(|m| m.text).collect();
        assert_eq!(texts, ["1", "tok", "\"str\"", "?1", "(\"x\" );p=2", ""]);
    }

    #[test]
    fn a_member_without_equals_is_boolean_true_and_not_a_string() {
        let d = parse_dictionary("sig2, other=\"v\"").unwrap();
        assert_eq!(d[0].value, Value::Item(Item { bare: Bare::Bool(true), params: vec![] }));
        assert_eq!(d[1].value, Value::Item(Item { bare: s("v"), params: vec![] }));
    }

    #[test]
    fn parse_item_takes_exactly_one_item() {
        let i = parse_item("  \"https://a.test\"  ").unwrap();
        assert_eq!((i.bare, i.params.is_empty()), (s("https://a.test"), true));
        assert_eq!(parse_item("\"a\";p=1").unwrap().params.len(), 1);
        for bad in ["", "\"a\", \"b\"", "\"a\" x", "k=\"a\"", "\"a", "(\"a\")x"] {
            assert!(parse_item(bad).is_none(), "{bad:?}");
        }
    }
}

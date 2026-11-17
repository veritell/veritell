#![no_main]
// Per-token use budgets: a sequence of operations on one
// `MemoryBudgetStore`, checked against a reference model, and its snapshot
// format (`export`, `import`) read and written across restarts.
//
// Input: the first byte is the capacity (0 to 7, so a full store is
// common). Then each operation is a tag byte and its argument bytes:
//
//   0 id b d    try_consume of id (8 of them) with budget b % 4, expiring d away
//   1 d         time moves forward by d * 3 seconds
//   2           restart: export, then import into a new store
//   3 n ...     import of a valid snapshot of n % 6 entries, each 3 bytes:
//               id, used, d (sorted and deduplicated here)
//   4 n ...     import of n raw bytes, as a damaged or hostile state file
//
// `d` is relative to now: below 0x80 after now, from 0x80 before now.
//
// Properties checked after every operation:
// - every outcome (Used, Spent, Full) and the stored entries equal the
//   model's; len() never exceeds the capacity;
// - an id is never Used more times than its budget allowed while it was
//   held, whatever the model says;
// - a restart keeps every live entry, byte for byte;
// - import never lowers an id's count of uses or its expiry, and adds no
//   new id beyond the capacity;
// - raw import succeeds exactly when the bytes follow the documented
//   format (checked by a separate reader), and on failure leaves the store
//   exactly as it was.
use std::collections::BTreeMap;
use veritell_token::{Consumed, MemoryBudgetStore};

const START: u64 = 1_800_000_000;

type Id = [u8; 16];

/// The store as documented: id -> (used, expires_at).
struct Model {
    capacity: usize,
    map: BTreeMap<Id, (u32, u64)>,
}

impl Model {
    fn try_consume(&mut self, id: Id, budget: u32, expires_at: u64, now: u64) -> Consumed {
        if budget == 0 {
            return Consumed::Spent;
        }
        if let Some((used, _)) = self.map.get_mut(&id) {
            if *used < budget {
                *used += 1;
                return Consumed::Used;
            }
            return Consumed::Spent;
        }
        if self.map.len() >= self.capacity {
            self.map.retain(|_, (_, exp)| *exp > now);
            if self.map.len() >= self.capacity {
                return Consumed::Full;
            }
        }
        self.map.insert(id, (1, expires_at));
        Consumed::Used
    }

    fn import(&mut self, entries: &[(Id, u32, u64)], now: u64) -> usize {
        let mut applied = 0;
        for &(id, used, exp) in entries {
            if exp <= now {
                continue;
            }
            if let Some(slot) = self.map.get_mut(&id) {
                *slot = (slot.0.max(used), slot.1.max(exp));
                applied += 1;
            } else if self.map.len() < self.capacity {
                self.map.insert(id, (used, exp));
                applied += 1;
            }
        }
        applied
    }

    fn export(&self, now: u64) -> Vec<u8> {
        let live: Vec<_> = self.map.iter().filter(|(_, v)| v.1 > now).collect();
        let mut out = vec![1];
        out.extend_from_slice(&(live.len() as u32).to_be_bytes());
        for (id, (used, exp)) in live {
            out.extend_from_slice(id);
            out.extend_from_slice(&used.to_be_bytes());
            out.extend_from_slice(&exp.to_be_bytes());
        }
        out
    }
}

/// The documented format, read apart from the crate: `None` when malformed.
fn read_snapshot(b: &[u8]) -> Option<Vec<(Id, u32, u64)>> {
    if b.len() < 5 || b[0] != 1 {
        return None;
    }
    let count = u32::from_be_bytes(b[1..5].try_into().unwrap()) as u64;
    if count * 28 + 5 != b.len() as u64 {
        return None;
    }
    let mut out: Vec<(Id, u32, u64)> = Vec::new();
    for e in b[5..].chunks(28) {
        let id: Id = e[..16].try_into().unwrap();
        let used = u32::from_be_bytes(e[16..20].try_into().unwrap());
        let exp = u64::from_be_bytes(e[20..28].try_into().unwrap());
        if used == 0 || out.last().is_some_and(|l| l.0 >= id) {
            return None;
        }
        out.push((id, used, exp));
    }
    Some(out)
}

fn rel(now: u64, d: u8) -> u64 {
    if d < 0x80 {
        now.saturating_add(u64::from(d) * 5)
    } else {
        now.saturating_sub(u64::from(d - 0x80) * 5)
    }
}

fn id(b: u8) -> Id {
    [b % 8; 16]
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&cap, mut ops)) = data.split_first() else { return };
    let capacity = usize::from(cap % 8);
    let mut store = MemoryBudgetStore::new(capacity);
    let mut model = Model {
        capacity,
        map: BTreeMap::new(),
    };
    let mut now = START;
    // Uses counted by this harness for ids the store holds without a
    // break (an import, or the id expiring and being dropped, resets it).
    let mut counted: BTreeMap<Id, u32> = BTreeMap::new();

    while let Some((&tag, rest)) = ops.split_first() {
        ops = rest;
        let mut arg = || {
            let (&b, rest) = ops.split_first().unwrap_or((&0, &[]));
            ops = rest;
            b
        };
        match tag % 5 {
            0 => {
                let id = id(arg());
                let budget = u32::from(arg() % 4);
                let exp = rel(now, arg());
                let was_held = model.map.contains_key(&id);
                let got = store.try_consume(&id, budget, exp, now);
                assert_eq!(got, model.try_consume(id, budget, exp, now), "try_consume differs from the model");
                // Ids the store dropped while purging start again.
                counted.retain(|k, _| model.map.contains_key(k));
                if got == Consumed::Used {
                    let n = counted.entry(id).or_insert(0);
                    if was_held {
                        *n += 1;
                        assert!(*n <= budget.max(1), "id used {n} times with budget {budget}");
                    } else {
                        *n = 1;
                    }
                }
            }
            1 => now = now.saturating_add(u64::from(arg()) * 3),
            2 => {
                let saved = store.export(now);
                let fresh = MemoryBudgetStore::new(capacity);
                let n = fresh.import(&saved, now).expect("an exported snapshot does not import");
                assert_eq!(n, model.map.values().filter(|v| v.1 > now).count());
                assert_eq!(fresh.export(now), saved, "a restart lost or changed entries");
                store = fresh;
                model.map.retain(|_, v| v.1 > now);
            }
            3 => {
                let mut entries: BTreeMap<Id, (u32, u64)> = BTreeMap::new();
                for _ in 0..arg() % 6 {
                    let (i, used, d) = (arg(), arg(), arg());
                    entries.insert(id(i), (u32::from(used).max(1), rel(now, d)));
                }
                let entries: Vec<_> = entries.into_iter().map(|(i, (u, e))| (i, u, e)).collect();
                let mut snap = vec![1];
                snap.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for (i, u, e) in &entries {
                    snap.extend_from_slice(i);
                    snap.extend_from_slice(&u.to_be_bytes());
                    snap.extend_from_slice(&e.to_be_bytes());
                }
                let before = read_snapshot(&store.export(0)).expect("export does not follow the format");
                let n = store.import(&snap, now).expect("a valid snapshot is refused");
                assert_eq!(n, model.import(&entries, now), "import applied a different number of entries");
                let after: BTreeMap<Id, (u32, u64)> = read_snapshot(&store.export(0))
                    .expect("export does not follow the format")
                    .into_iter()
                    .map(|(i, u, e)| (i, (u, e)))
                    .collect();
                for (k, used, exp) in before {
                    let (u2, e2) = after.get(&k).copied().expect("import dropped an id");
                    assert!(u2 >= used && e2 >= exp, "import lowered a budget or an expiry");
                }
                counted.clear();
            }
            _ => {
                let n = usize::from(arg());
                let raw: Vec<u8> = (0..n).map(|_| arg()).collect();
                let before = store.export(0);
                match (store.import(&raw, now), read_snapshot(&raw)) {
                    (Ok(n), Some(entries)) => {
                        assert_eq!(n, model.import(&entries, now));
                        counted.clear();
                    }
                    (Err(e), None) => {
                        assert!(!e.to_string().is_empty());
                        assert_eq!(store.export(0), before, "a refused snapshot changed the store");
                    }
                    (got, want) => panic!("import {got:?}, but the format says {:?}", want.map(|e| e.len())),
                }
            }
        }
        assert!(store.len() <= capacity, "{} entries over capacity {capacity}", store.len());
        assert_eq!(store.is_empty(), store.len() == 0);
        assert_eq!(store.export(now), model.export(now), "stored entries differ from the model");
    }
});

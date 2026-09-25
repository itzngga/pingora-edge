//! Name-stable route identity (std only). A route keeps its breaker slot and its rate
//! uid across reorders and reloads; a removed route's slot is handed to another only
//! after RETIRE, and a uid is never handed to a different route.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Breaker slots (breaker.rs SLOTS); an id past it fails open.
pub const SLOTS: usize = 1024;
/// No breaker slot: the route is never short-circuited.
pub const NO_SLOT: usize = usize::MAX;
/// A removed route's slot stays reserved this long, so a torn write or a quick
/// remove + re-add gets its own breaker back instead of another route's.
pub const RETIRE: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub slot: usize,
    pub uid: u32,
}

#[derive(Clone, Copy, Debug)]
enum Slot {
    Free,
    Live,
    Retired(Instant),
}

pub struct Assignment {
    /// Per route, file order.
    pub ids: Vec<Ids>,
    /// Slots taken over from a route retired ≥ RETIRE ago: their breaker state must be reset.
    pub reset: Vec<usize>,
    /// Positions (file order) left without a breaker slot (all 1024 in use or reserved).
    pub unslotted: Vec<usize>,
}

#[derive(Clone)]
pub struct RouteIds {
    live: HashMap<String, Ids>,
    retired: HashMap<String, (Ids, Instant)>,
    slots: Vec<Slot>,
    next_uid: u32,
}

impl Default for RouteIds {
    fn default() -> Self {
        Self {
            live: HashMap::new(),
            retired: HashMap::new(),
            slots: vec![Slot::Free; SLOTS],
            next_uid: 0,
        }
    }
}

/// Identities made unique: a later duplicate (e.g. a literal "a#1" next to a repeated
/// "a") is keyed by its position too, so two routes never share state.
fn unique_keys(identities: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    identities
        .iter()
        .enumerate()
        .map(|(i, id)| {
            if seen.insert(id.as_str()) {
                id.clone()
            } else {
                format!("{}@{}", id, i)
            }
        })
        .collect()
}

impl RouteIds {
    /// Ids for `identities` (file order) as of `now`. On a fresh table this is
    /// slot = uid = position (slot NO_SLOT past 1024), i.e. exactly the boot ids.
    pub fn assign(&mut self, identities: &[String], now: Instant) -> Assignment {
        let keys = unique_keys(identities);
        let wanted: HashSet<&str> = keys.iter().map(String::as_str).collect();

        let gone: Vec<String> = self
            .live
            .keys()
            .filter(|k| !wanted.contains(k.as_str()))
            .cloned()
            .collect();
        for k in gone {
            if let Some(ids) = self.live.remove(&k) {
                if let Some(s) = self.slots.get_mut(ids.slot) {
                    *s = Slot::Retired(now);
                }
                self.retired.insert(k, (ids, now));
            }
        }
        self.retired
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < RETIRE);

        let mut out = Assignment {
            ids: Vec::with_capacity(keys.len()),
            reset: Vec::new(),
            unslotted: Vec::new(),
        };
        for (i, key) in keys.into_iter().enumerate() {
            let ids = match self.live.get(&key).copied() {
                Some(ids) if ids.slot != NO_SLOT => ids,
                // A live route left slotless takes the first slot that frees up; its uid stays.
                Some(ids) => match self.free_slot(now, &mut out.reset) {
                    NO_SLOT => ids,
                    slot => {
                        if let Some(s) = self.slots.get_mut(slot) {
                            *s = Slot::Live;
                        }
                        let ids = Ids { slot, uid: ids.uid };
                        self.live.insert(key, ids);
                        ids
                    }
                },
                None => {
                    let ids = match self.retired.remove(&key) {
                        Some((ids, _)) => ids,
                        None => {
                            let slot = self.free_slot(now, &mut out.reset);
                            let uid = self.next_uid;
                            // u32::MAX is the /_v bucket's; 4 billion routes later the last uid repeats.
                            if self.next_uid < u32::MAX - 1 {
                                self.next_uid += 1;
                            }
                            Ids { slot, uid }
                        }
                    };
                    if let Some(s) = self.slots.get_mut(ids.slot) {
                        *s = Slot::Live;
                    }
                    self.live.insert(key, ids);
                    ids
                }
            };
            if ids.slot == NO_SLOT {
                out.unslotted.push(i);
            }
            out.ids.push(ids);
        }
        out
    }

    /// The lowest never-used slot, else the lowest one retired ≥ RETIRE ago (reported for reset).
    fn free_slot(&self, now: Instant, reset: &mut Vec<usize>) -> usize {
        if let Some(i) = self.slots.iter().position(|s| matches!(s, Slot::Free)) {
            return i;
        }
        let expired = self.slots.iter().position(|s| match s {
            Slot::Retired(at) => now.saturating_duration_since(*at) >= RETIRE,
            _ => false,
        });
        match expired {
            Some(i) => {
                reset.push(i);
                i
            }
            None => NO_SLOT,
        }
    }
}

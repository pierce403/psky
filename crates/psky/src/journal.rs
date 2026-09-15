//! Bounded operator events and action history.
//!
//! Messages are fixed application diagnostics. Never log request bodies,
//! bearer tokens, upstream response bodies, or raw exception strings here.

use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// Maximum diagnostic events kept in memory per process.
pub const LOG_CAPACITY: usize = 200;
/// Maximum completed actions kept in memory per process.
pub const OPERATION_CAPACITY: usize = 32;

/// Unix time in whole seconds, used for diagnostic timestamps only.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One sanitized process event. Sequence numbers reset on restart.
#[derive(Clone, Serialize)]
pub struct Event {
    /// Increasing local cursor.
    pub sequence: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// Application severity: info, warning, or error.
    pub level: &'static str,
    /// Stable application event name.
    pub event: &'static str,
    /// Fixed diagnostic text, never arbitrary user or upstream input.
    pub message: &'static str,
}

/// Cursor page from the process-local ring buffer.
#[derive(Serialize)]
pub struct LogPage {
    /// Events strictly after the requested cursor, oldest first.
    pub entries: Vec<Event>,
    /// Cursor for the next request.
    pub next_cursor: u64,
    /// Highest evicted sequence, or zero when nothing was evicted.
    pub dropped_before: u64,
    /// Whether entries since the cursor have already been evicted.
    pub truncated: bool,
}

/// In-memory ring of sanitized application events.
#[derive(Default)]
pub struct Journal {
    entries: VecDeque<Event>,
    sequence: u64,
}

impl Journal {
    /// Append a fixed event, evicting the oldest when full.
    pub fn push(&mut self, level: &'static str, event: &'static str, message: &'static str) {
        self.sequence += 1;
        if self.entries.len() == LOG_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Event {
            sequence: self.sequence,
            timestamp: now(),
            level,
            event,
            message,
        });
    }

    /// Read bounded events; callers must validate the requested page size.
    pub fn page(&self, after: u64, limit: usize) -> LogPage {
        let dropped_before = self.entries.front().map_or(0, |e| e.sequence - 1);
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.sequence > after)
            .take(limit.min(LOG_CAPACITY))
            .cloned()
            .collect();
        let next_cursor = entries.last().map_or(self.sequence, |e| e.sequence);
        LogPage {
            entries,
            next_cursor,
            dropped_before,
            truncated: after < dropped_before,
        }
    }

    /// Last sequence, used to detect an agent carrying a cursor across restart.
    pub fn last_sequence(&self) -> u64 {
        self.sequence
    }
}

/// Supported asynchronous operator action.
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Bounded reads from configured Hypersnap peers.
    Preflight,
    /// Synthetic local repository reconstruction.
    Reconstruct,
}

/// One process-local operator action. It never represents a production write.
#[derive(Clone, Serialize)]
pub struct Operation {
    /// Increasing action identifier, scoped to the process instance.
    pub id: u64,
    /// Action type.
    pub kind: OperationKind,
    /// running, succeeded (report produced), or failed.
    pub status: &'static str,
    /// Unix seconds.
    pub started_at: u64,
    /// Unix seconds when finished, otherwise null.
    pub finished_at: Option<u64>,
    /// Sanitized failure category, otherwise null.
    pub error: Option<&'static str>,
    /// Settings revision used by this action.
    pub config_revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paging_is_bounded_and_reports_eviction() {
        let mut journal = Journal::default();
        for _ in 0..205 {
            journal.push("info", "test", "fixed");
        }
        let page = journal.page(0, 2);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].sequence, 6);
        assert_eq!(page.dropped_before, 5);
        assert!(page.truncated);
        assert_eq!(page.next_cursor, 7);
        assert!(!journal.page(7, 200).truncated);
        assert!(journal.page(205, 200).entries.is_empty());
        assert_eq!(journal.page(205, 200).next_cursor, 205);
    }
}

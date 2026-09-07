//! Caller-owned DNS work sharing. Dropping every caller also drops the network work.
use anyhow::{Result, bail};
use hickory_proto::op::Message;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

type SharedResult = Arc<std::result::Result<Message, String>>;

#[derive(Clone)]
enum State {
    Pending,
    Finished(SharedResult),
    Abandoned,
}

struct Entry {
    state: watch::Sender<State>,
}

#[derive(Default)]
pub(crate) struct Flights {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

pub(crate) enum Ticket<'a> {
    Owner(Owner<'a>),
    Follower(Follower),
}

pub(crate) struct Owner<'a> {
    flights: &'a Flights,
    key: String,
    entry: Arc<Entry>,
    finished: bool,
}

pub(crate) struct Follower {
    state: watch::Receiver<State>,
}

impl Flights {
    pub(crate) fn join(&self, key: &str) -> Result<Ticket<'_>> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(key) {
            return Ok(Ticket::Follower(Follower {
                state: entry.state.subscribe(),
            }));
        }
        if entries.len() >= 512 {
            bail!("Concurrent DNS query limit reached");
        }
        let entry = Arc::new(Entry {
            state: watch::channel(State::Pending).0,
        });
        entries.insert(key.into(), entry.clone());
        Ok(Ticket::Owner(Owner {
            flights: self,
            key: key.into(),
            entry,
            finished: false,
        }))
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Owner<'_> {
    pub(crate) fn finish(mut self, result: &Result<Message>) {
        let shared = Arc::new(match result {
            Ok(message) => Ok(message.clone()),
            Err(error) => Err(format!("{error:#}")),
        });
        self.entry.state.send_replace(State::Finished(shared));
        self.finished = true;
    }
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        let mut entries = self.flights.entries.lock().unwrap();
        if entries
            .get(&self.key)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
        {
            entries.remove(&self.key);
        }
        if !self.finished {
            self.entry.state.send_replace(State::Abandoned);
        }
    }
}

impl Follower {
    // None lets a surviving caller take ownership after the original caller is cancelled.
    pub(crate) async fn wait(mut self) -> Option<Result<Message>> {
        loop {
            let current = self.state.borrow_and_update().clone();
            match current {
                State::Pending => {
                    if self.state.changed().await.is_err() {
                        return None;
                    }
                }
                State::Finished(result) => {
                    return Some(result.as_ref().clone().map_err(anyhow::Error::msg));
                }
                State::Abandoned => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unique_inflight_work_is_bounded_and_cancelled_owners_release_capacity() {
        let flights = Flights::default();
        let mut tickets = (0..512)
            .map(|index| flights.join(&index.to_string()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(flights.len(), 512);
        assert!(flights.join("overflow").is_err());
        assert!(matches!(flights.join("0"), Ok(Ticket::Follower(_))));
        tickets.pop();
        assert!(flights.join("replacement").is_ok());
        drop(tickets);
        assert_eq!(flights.len(), 0);
    }
}

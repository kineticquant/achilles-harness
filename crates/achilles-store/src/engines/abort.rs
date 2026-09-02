//! Cooperative scan abort. CPU loops poll the flag; HTTP futures race it so
//! dropping the request actually tears the socket down.
//! Apache-2.0.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scan cancelled")
    }
}

impl std::error::Error for Cancelled {}

#[derive(Clone)]
pub struct Abort {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Abort {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn flag(&self) -> &AtomicBool {
        self.flag.as_ref()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Resolves as soon as [`Self::cancel`] runs (including if it already did).
    pub async fn cancelled(&self) {
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }

    /// Drop `fut` the moment cancel lands so reqwest aborts the in-flight call.
    pub async fn race<T>(&self, fut: impl Future<Output = T>) -> Result<T, Cancelled> {
        tokio::select! {
            biased;
            _ = self.cancelled() => Err(Cancelled),
            v = fut => Ok(v),
        }
    }
}

impl Default for Abort {
    fn default() -> Self {
        Self::new()
    }
}

pub fn flagged(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

pub fn is_cancel(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Cancelled>().is_some() || err.to_string().contains("scan cancelled")
}

pub async fn http<T>(
    abort: Option<&Abort>,
    fut: impl Future<Output = Result<T, reqwest::Error>>,
) -> anyhow::Result<T> {
    match abort {
        None => Ok(fut.await?),
        Some(abort) => match abort.race(fut).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(err.into()),
            Err(cancelled) => Err(cancelled.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn race_drops_hanging_future_on_cancel() {
        let abort = Abort::new();
        let started = Instant::now();
        let abort_bg = abort.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            abort_bg.cancel();
        });
        let result = abort
            .race(async {
                tokio::time::sleep(Duration::from_secs(8)).await;
                "done"
            })
            .await;
        assert_eq!(result, Err(Cancelled));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn already_cancelled_race_returns_immediately() {
        let abort = Abort::new();
        abort.cancel();
        let started = Instant::now();
        let result = abort
            .race(async {
                tokio::time::sleep(Duration::from_secs(8)).await;
                1
            })
            .await;
        assert_eq!(result, Err(Cancelled));
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}

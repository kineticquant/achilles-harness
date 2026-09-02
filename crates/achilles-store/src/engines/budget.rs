//! Wall-clock and BYO spend caps. Hitting a cap is a graceful stop, not a
//! failure — resume the same assessment to continue. Apache-2.0.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    Duration,
    Cost,
}

#[derive(Debug, Clone)]
pub struct BudgetExceeded {
    pub kind: CapKind,
    pub message: String,
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BudgetExceeded {}

#[derive(Clone)]
pub struct ScanBudget {
    started: Instant,
    max_duration: Option<Duration>,
    max_cost_usd: Option<f64>,
    spent_usd: Arc<Mutex<f64>>,
}

impl ScanBudget {
    pub fn new(max_duration_secs: Option<u64>, max_cost_usd: Option<f64>) -> Self {
        Self {
            started: Instant::now(),
            max_duration: max_duration_secs.map(Duration::from_secs),
            max_cost_usd: max_cost_usd.filter(|v| *v > 0.0),
            spent_usd: Arc::new(Mutex::new(0.0)),
        }
    }

    pub fn spent_usd(&self) -> f64 {
        self.spent_usd.lock().map(|g| *g).unwrap_or(0.0)
    }

    pub fn add_cost(&self, cost_usd: Option<f64>) -> Result<()> {
        if let Some(cost) = cost_usd.filter(|v| *v > 0.0) {
            if let Ok(mut spent) = self.spent_usd.lock() {
                *spent += cost;
            }
        }
        self.check()
    }

    pub fn check(&self) -> Result<()> {
        if let Some(max) = self.max_duration {
            if self.started.elapsed() >= max {
                anyhow::bail!(BudgetExceeded {
                    kind: CapKind::Duration,
                    message: format!(
                        "stopped: max duration {}s — resume this assessment to continue",
                        max.as_secs()
                    ),
                });
            }
        }
        if let Some(max) = self.max_cost_usd {
            if self.spent_usd() >= max {
                anyhow::bail!(BudgetExceeded {
                    kind: CapKind::Cost,
                    message: format!(
                        "stopped: max cost ${max:.4} — resume this assessment to continue"
                    ),
                });
            }
        }
        Ok(())
    }
}

pub fn is_budget(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BudgetExceeded>().is_some() || err.to_string().starts_with("stopped: max ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_zero_trips_immediately() {
        let budget = ScanBudget::new(Some(0), None);
        assert!(is_budget(&budget.check().unwrap_err()));
    }

    #[test]
    fn cost_cap_trips_after_add() {
        let budget = ScanBudget::new(None, Some(0.5));
        budget.add_cost(Some(0.4)).unwrap();
        assert!(is_budget(&budget.add_cost(Some(0.2)).unwrap_err()));
    }
}

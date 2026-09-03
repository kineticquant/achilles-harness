//! Scan depth: each tier includes the previous, then expands.
//! Fast = engines only. Investigate = Fast ledger + dual AI review of those
//! hits. Deep = Investigate + a heavy function-by-function model pass.
//! Apache-2.0.

use crate::engines::walk::WalkOpts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDepth {
    /// Engines only. Seconds.
    Fast,
    /// Fast findings stay on the ledger; the model reviews code/config hits.
    Investigate,
    /// Investigate plus a wide function-unit model inspection.
    Deep,
}

impl ScanDepth {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "investigate" | "standard" | "middle" => Self::Investigate,
            "deep" | "full" => Self::Deep,
            _ => Self::Fast,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Investigate => "investigate",
            Self::Deep => "deep",
        }
    }

    pub fn runs_investigate(self) -> bool {
        !matches!(self, Self::Fast)
    }

    /// How many Fast engine hits the model dual-reviews (investigator + validator).
    pub fn max_review(self) -> usize {
        match self {
            Self::Fast => 0,
            Self::Investigate => 80,
            Self::Deep => 250,
        }
    }

    /// How many function bodies Deep asks the model to inspect. Investigate: none.
    pub fn max_units(self) -> usize {
        match self {
            Self::Deep => 160,
            _ => 0,
        }
    }

    /// JSON agent turns allowed per review/unit (read/grep/ledger + verdict).
    pub fn max_turns(self) -> usize {
        match self {
            Self::Deep => 16,
            Self::Investigate => 12,
            Self::Fast => 0,
        }
    }

    pub fn max_workers(self) -> usize {
        match self {
            Self::Deep => 4,
            _ => 3,
        }
    }

    pub fn walk_opts(self, include_vendor: bool) -> WalkOpts {
        WalkOpts {
            include_vendor,
            max_files: if matches!(self, Self::Deep) {
                16_000
            } else {
                WalkOpts::default().max_files
            },
            ..WalkOpts::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aliases() {
        assert_eq!(ScanDepth::parse("light"), ScanDepth::Fast);
        assert_eq!(ScanDepth::parse("quick"), ScanDepth::Fast);
        assert_eq!(ScanDepth::parse("investigate"), ScanDepth::Investigate);
        assert_eq!(ScanDepth::parse("deep"), ScanDepth::Deep);
    }

    #[test]
    fn each_tier_expands_the_previous() {
        assert_eq!(ScanDepth::Fast.max_review(), 0);
        assert!(ScanDepth::Investigate.max_review() > 0);
        assert!(ScanDepth::Deep.max_review() >= ScanDepth::Investigate.max_review());
        assert_eq!(ScanDepth::Investigate.max_units(), 0);
        assert!(ScanDepth::Deep.max_units() > ScanDepth::Investigate.max_units());
        assert!(ScanDepth::Deep.max_turns() >= ScanDepth::Investigate.max_turns());
        assert!(
            ScanDepth::Deep.walk_opts(false).max_files
                >= ScanDepth::Fast.walk_opts(false).max_files
        );
    }
}

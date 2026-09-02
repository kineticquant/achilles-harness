//! Achilles AppSec system of record (`achilles.db`) plus scan engines.
//!
//! Public HTTP intel hosts are listed in [`public_sources`] — OSV, KEV, EPSS,
//! NVD, GitHub Advisories, deps.dev, OpenSSF Scorecard, optional Socket.
//! Point `ACHILLES_INTEL_BASE` at Rancero/trivault later; URL map stays here.
//!
//! Apache-2.0. Not part of upstream goose.

pub mod acp;
pub mod brief;
pub mod engines;
pub mod public_sources;
pub mod scan;
pub mod seed;
pub mod store;
pub mod types;

pub use seed::seed_bundled_review_checks;
pub use store::AchillesStore;
pub use types::{
    Assessment, AssessmentStatus, Candidate, CandidateStatus, CoverageSnapshot, Engagement,
    Finding, FindingEvent, HandleBlob, Severity, WorkUnit, WorkUnitDecision,
};

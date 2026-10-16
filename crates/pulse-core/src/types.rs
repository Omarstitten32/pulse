//! Shared types for the security engines.
//!
//! Engines that produce a 0-100 score MUST report a [`Confidence`]
//! level alongside it. This lets consumers distinguish:
//!
//!   - "we scanned everything, the score is meaningful"
//!   - "we scanned nothing, the score is undefined"
//!
//! The same binary runs on Kali (root), Termux (non-root), Android
//! shell, Linux servers, and containers. In each environment the set
//! of readable sources differs, so the score alone is not enough.

use serde::{Deserialize, Serialize};

/// How much of the expected data was actually readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Confidence {
    /// >= 80% of expected sources were readable. Score is meaningful.
    High,
    /// 50-79% readable. Score is indicative.
    Medium,
    /// 1-49% readable. Score is a lower bound on the true score.
    Low,
    /// 0% readable. Score is `None` and must not be interpreted.
    ///
    /// This is the [`Default`] because an uninitialized report has read nothing.
    #[default]
    None,
}

impl Confidence {
    /// Compute the level from `read` and `total` source counts.
    ///
    /// `total == 0` and `read == 0` both yield [`Confidence::None`].
    pub fn from_counts(read: u32, total: u32) -> Self {
        if total == 0 || read == 0 {
            return Self::None;
        }
        let pct = (read as f64 / total as f64) * 100.0;
        if pct >= 80.0 {
            Self::High
        } else if pct >= 50.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::None => "None",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_total_is_none() {
        assert_eq!(Confidence::from_counts(0, 0), Confidence::None);
        assert_eq!(Confidence::from_counts(5, 0), Confidence::None);
    }

    #[test]
    fn zero_read_is_none() {
        assert_eq!(Confidence::from_counts(0, 10), Confidence::None);
    }

    #[test]
    fn boundaries() {
        assert_eq!(Confidence::from_counts(1, 10), Confidence::Low);
        assert_eq!(Confidence::from_counts(4, 10), Confidence::Low);
        assert_eq!(Confidence::from_counts(5, 10), Confidence::Medium);
        assert_eq!(Confidence::from_counts(7, 10), Confidence::Medium);
        assert_eq!(Confidence::from_counts(8, 10), Confidence::High);
        assert_eq!(Confidence::from_counts(10, 10), Confidence::High);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(Confidence::High.label(), "High");
        assert_eq!(Confidence::Medium.label(), "Medium");
        assert_eq!(Confidence::Low.label(), "Low");
        assert_eq!(Confidence::None.label(), "None");
    }

    #[test]
    fn all_variants_round_trip_through_json() {
        for c in [
            Confidence::High,
            Confidence::Medium,
            Confidence::Low,
            Confidence::None,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let back: Confidence = serde_json::from_str(&j).unwrap();
            assert_eq!(c, back);
        }
    }
}

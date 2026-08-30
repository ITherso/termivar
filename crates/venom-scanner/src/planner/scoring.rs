use serde::{Deserialize, Deserializer, Serialize};
use venom_core::Probability;

use crate::planner::PlannerError;

const MAX_BASIS_POINTS: u16 = 10_000;

/// Normalized gain or business-value score in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BenefitScore(u16);

impl BenefitScore {
    /// No expected benefit.
    pub const NONE: Self = Self(0);

    /// Maximum normalized benefit.
    pub const MAX: Self = Self(MAX_BASIS_POINTS);

    /// Creates a benefit score from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, PlannerError> {
        if value > MAX_BASIS_POINTS {
            return Err(PlannerError::BenefitOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a benefit score from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, PlannerError> {
        Self::from_basis_points(u16::from(value) * 100)
    }

    /// Returns the normalized score in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for BenefitScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// Normalized operational risk in non-zero basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RiskScore(u16);

impl RiskScore {
    /// Maximum normalized risk.
    pub const MAX: Self = Self(MAX_BASIS_POINTS);

    /// Creates a non-zero risk score from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, PlannerError> {
        if value == 0 || value > MAX_BASIS_POINTS {
            return Err(PlannerError::RiskOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a non-zero risk score from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, PlannerError> {
        Self::from_basis_points(u16::from(value) * 100)
    }

    /// Returns the normalized score in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// Positive estimated execution cost in planner-defined units.
///
/// A deployment may define one unit as one request, one second, or another
/// consistent resource measure. Actions in one planner must use the same unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionCost(u32);

impl ActionCost {
    /// Creates a positive execution cost.
    pub fn new(units: u32) -> Result<Self, PlannerError> {
        if units == 0 {
            return Err(PlannerError::ZeroCost);
        }
        Ok(Self(units))
    }

    /// Returns the estimated cost units.
    pub const fn units(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ActionCost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Fixed-point utility used only for deterministic ordering.
///
/// The value is not a probability. It is calculated as
/// `gain * confidence * business_value / cost / risk` using the integer units
/// exposed by each input type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtilityScore(u64);

impl UtilityScore {
    /// Zero utility.
    pub const ZERO: Self = Self(0);

    /// Smallest positive utility accepted by a default planning context.
    pub const MIN_POSITIVE: Self = Self(1);

    /// Creates a threshold or persisted score from raw utility units.
    pub const fn from_units(units: u64) -> Self {
        Self(units)
    }

    /// Returns raw fixed-point utility units.
    pub const fn units(self) -> u64 {
        self.0
    }
}

/// Explainable inputs and result of one utility calculation.
///
/// # Example
///
/// ```rust
/// use venom_core::Probability;
/// use venom_scanner::{ActionCost, BenefitScore, RiskScore, UtilityBreakdown};
///
/// let utility = UtilityBreakdown::calculate(
///     BenefitScore::from_percent(80)?,
///     Probability::from_percent(75)?,
///     BenefitScore::from_percent(90)?,
///     ActionCost::new(100)?,
///     RiskScore::from_percent(20)?,
/// );
///
/// assert_eq!(utility.score().units(), 270_000_000);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UtilityBreakdown {
    gain: BenefitScore,
    confidence: Probability,
    business_value: BenefitScore,
    pub(super) cost: ActionCost,
    risk: RiskScore,
    pub(super) score: UtilityScore,
}

impl<'de> Deserialize<'de> for UtilityBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireUtility {
            gain: BenefitScore,
            confidence: Probability,
            business_value: BenefitScore,
            cost: ActionCost,
            risk: RiskScore,
            score: UtilityScore,
        }

        let wire = WireUtility::deserialize(deserializer)?;
        let utility = Self::calculate(
            wire.gain,
            wire.confidence,
            wire.business_value,
            wire.cost,
            wire.risk,
        );
        if utility.score != wire.score {
            return Err(serde::de::Error::custom(format!(
                "serialized utility {} does not match computed utility {}",
                wire.score.units(),
                utility.score.units()
            )));
        }
        Ok(utility)
    }
}

impl UtilityBreakdown {
    /// Calculates utility with integer arithmetic and half-up rounding.
    pub fn calculate(
        gain: BenefitScore,
        confidence: Probability,
        business_value: BenefitScore,
        cost: ActionCost,
        risk: RiskScore,
    ) -> Self {
        let numerator = u128::from(gain.basis_points())
            * u128::from(confidence.parts_per_million())
            * u128::from(business_value.basis_points());
        let denominator = u128::from(cost.units()) * u128::from(risk.basis_points());
        let rounded = (numerator + denominator / 2) / denominator;
        let score = u64::try_from(rounded).expect("validated utility factors fit in u64");
        Self {
            gain,
            confidence,
            business_value,
            cost,
            risk,
            score: UtilityScore(score),
        }
    }

    /// Returns expected information or security gain.
    pub fn gain(&self) -> BenefitScore {
        self.gain
    }

    /// Returns the selected Bayesian hypothesis posterior.
    pub fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns target business value.
    pub fn business_value(&self) -> BenefitScore {
        self.business_value
    }

    /// Returns estimated execution cost.
    pub fn cost(&self) -> ActionCost {
        self.cost
    }

    /// Returns normalized operational risk.
    pub fn risk(&self) -> RiskScore {
        self.risk
    }

    /// Returns the final fixed-point utility.
    pub fn score(&self) -> UtilityScore {
        self.score
    }
}

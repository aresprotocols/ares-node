use super::*;

/// Import the template pallet.
pub use staking_extend;

/// Configure the pallet template in pallets/template.
impl staking_extend::Config for Runtime {
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ValidatorSet = Historical;
}

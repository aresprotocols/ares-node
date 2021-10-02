use super::*;

/// Import the template pallet.
pub use member_extend;

/// Configure the pallet template in pallets/template.
impl member_extend::Config for Runtime {
    type MemberAuthority = sp_consensus_babe::AuthorityId ;
    type Member = Babe;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
}

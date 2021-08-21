use super::*;
use pallet_ocw;

// use sp_runtime::{
//     app_crypto::{app_crypto, sr25519},
//     traits::Verify,
// };

// An index to a block.
pub type BlockNumber = u32;

parameter_types! {
	pub const GracePeriod: BlockNumber = 5;
	pub const UnsignedInterval: u32 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl pallet_ocw::Config for Runtime {
    type Event = Event;
    type Call = Call;
    type AuthorityId = pallet_ocw::crypto::OcwAuthId ;
    type GracePeriod = GracePeriod;
    type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
}

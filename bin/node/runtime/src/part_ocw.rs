use super::*;
use pallet_ocw;
parameter_types! {
	pub const GracePeriod: BlockNumber = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}
impl pallet_ocw::Config for Runtime {
    type Event = Event;
    type Call = Call;
    type AuthorityId = pallet_ocw::crypto::TestAuthId;
    type GracePeriod = GracePeriod;
}
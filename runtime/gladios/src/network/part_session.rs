use super::*;
use constants::time::EPOCH_DURATION_IN_BLOCKS;
pub use pallet_session;
use sp_runtime::{impl_opaque_keys, traits::OpaqueKeys};

parameter_types! {
	pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(17);
	pub const Period: u32 = EPOCH_DURATION_IN_BLOCKS as u32;
	pub const Offset: u32 = 0;
}

impl_opaque_keys! {
	pub struct SessionKeys {
		pub babe: Babe,
		pub grandpa: Grandpa,
		pub ares: AresOracle,
		pub authority_discovery: AuthorityDiscovery,
	}
}

impl pallet_session::Config for Runtime {
	type Event = Event;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = pallet_staking::StashOf<Self>;
	type ShouldEndSession = Babe;
	type NextSessionRotation = Babe;
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Self, Staking>;
	type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type DisabledValidatorsThreshold = DisabledValidatorsThreshold;
	type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

impl pallet_session::historical::Config for Runtime {
	type FullIdentification = pallet_staking::Exposure<AccountId, Balance>;
	type FullIdentificationOf = pallet_staking::ExposureOf<Runtime>;
}

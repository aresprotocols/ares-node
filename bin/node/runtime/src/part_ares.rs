use super::*;

use pallet_ares;
/// create the ares pallet const vars.
parameter_types! {
	pub const ValidityPeriod: u32 = 50;
	pub const AggregateQueueNum: u32 = 10;
	pub const AggregateInterval: BlockNumber = 15;
}

impl pallet_ares::Config for Runtime {
    type Event = Event;
    type ValidityPeriod = ValidityPeriod;
    type AggregateQueueNum = AggregateQueueNum;
    type AggregateInterval = AggregateInterval;
}

// TODO:: not move . https://github.com/aresprotocols/Ares-Dapp/blob/8f5beaac27f13ef994c1383ce7069e34e7ab8bc2/Ares/runtime/src/chain_extension.rs
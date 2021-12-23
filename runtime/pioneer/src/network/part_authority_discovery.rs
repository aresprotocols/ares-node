use super::*;

parameter_types! {
	pub const MaxAuthorities: u32 = 100;
}

impl pallet_authority_discovery::Config for Runtime {
	type MaxAuthorities = MaxAuthorities;
}
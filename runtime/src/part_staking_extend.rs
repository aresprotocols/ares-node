use super::*;
use frame_election_provider_support::{ElectionProvider, onchain};
use frame_support::traits::OneSessionHandler;
// use ares_oracle::crypto2::AuraAuthId;

impl staking_extend::Config for Runtime {
    type ValidatorId = AccountId ; //<Self as frame_system::Config>::AccountId;
    type ValidatorSet = Historical;
    type AuthorityId = pallet_babe::AuthorityId ;// <AresOracle as ares_oracle::Config>::AuthorityAres ;// AuraId;
    type DataProvider = Staking;
    type ElectionProvider = ElectionProviderMultiPhase;
    type OnChainAccuracy = Perbill;
    type GenesisElectionProvider = onchain::OnChainSequentialPhragmen<
        pallet_election_provider_multi_phase::OnChainConfig<Self>,
    >;
    type AresOraclePreCheck = AresOracle;
}
use super::*;
use codec::Encode;
use frame_support::sp_runtime::app_crypto::Public;
use frame_support::sp_runtime::generic::{Era, SignedPayload};
use frame_support::sp_runtime::traits;
use frame_support::sp_runtime::traits::AccountIdConversion;
use frame_support::traits::FindAuthor;
use frame_support::ConsensusEngineId;
use ares_oracle;
use ares_oracle::Config;
use sp_runtime::traits::StaticLookup;
use sp_runtime::{MultiAddress, SaturatedConversion};
use crate::governance::part_technical::TechnicalCollective;
pub use ares_oracle::LOCAL_STORAGE_PRICE_REQUEST_DOMAIN;
// use sp_consensus_babe::AuthorityId as BabeId;
use pallet_babe::AuthorityId as BabeId;

// An index to a block.
pub type BlockNumber = u32;

pub type EnsureRootOrHalfTechnicalCollective = EnsureOneOf<
	AccountId,
	EnsureRoot<AccountId>,
	pallet_collective::EnsureProportionAtLeast<_1, _2, AccountId, TechnicalCollective>,
>;

parameter_types! {
	pub const UnsignedPriority: u64 = 1 << 20;
	pub const CalculationKind: u8 = 1;
	pub const ErrLogPoolDepth: u32 = 1000;
}

impl ares_oracle::babe_handler::Config for Runtime {
	type AuthorityId = BabeId;
}

impl ares_oracle::Config for Runtime {
	type Event = Event;
	type Call = Call;
	type OffchainAppCrypto = ares_oracle::AresCrypto::<AresId>;
	type AuthorityAres = AresId;
	type UnsignedPriority = UnsignedPriority;
	type FindAuthor = Babe;
	type CalculationKind = CalculationKind;
	type RequestOrigin = EnsureRootOrHalfTechnicalCollective ;
	type AuthorityCount = AresOracle;
	type OracleFinanceHandler = OracleFinance;
	type AresIStakingNpos = Self;
	type ErrLogPoolDepth = ErrLogPoolDepth;
}

//
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	Call: From<LocalCall>,
{
	//
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call,
		public: <Signature as traits::Verify>::Signer,
		account: AccountId,
		nonce: Index,
	) -> Option<(Call, <UncheckedExtrinsic as traits::Extrinsic>::SignaturePayload)> {
		let tip = 0;
		// take the biggest period possible.
		let period =
			BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2) as u64;
		let current_block = System::block_number()
			.saturated_into::<u64>()
			// The `System::block_number` is initialized with `n+1`,
			// so the actual block number is `n`.
			.saturating_sub(1);
		let era = Era::mortal(period, current_block);
		let extra = (
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckEra::<Runtime>::from(era),
			frame_system::CheckNonce::<Runtime>::from(nonce),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
		);

		//
		let raw_payload = SignedPayload::new(call, extra)
			.map_err(|e| {
				log::warn!("Unable to create signed payload: {:?}", e);
			})
			.ok()?;
		let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
		// let address = Indices::unlookup(account);
		let address = MultiAddress::Id(account);
		let (call, extra, _) = raw_payload.deconstruct();
		Some((call, (address, signature.into(), extra)))
	}
}

impl frame_system::offchain::SigningTypes for Runtime {
	type Public = <Signature as traits::Verify>::Signer;
	type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
	Call: From<C>,
{
	type Extrinsic = UncheckedExtrinsic;
	type OverarchingCall = Call;
}

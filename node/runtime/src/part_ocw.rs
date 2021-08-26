use super::*;
use pallet_ocw;

// An index to a block.
pub type BlockNumber = u32;

parameter_types! {
	pub const GracePeriod: BlockNumber = 5;
	pub const UnsignedInterval: u32 = 10;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl pallet_ocw::Config for Runtime {
    type Event = Event;
    type Call = Call;
    type AuthorityId = pallet_ocw::crypto::OcwAuthId ;
    type AuthorityId2 = pallet_ocw::sr25519::AuthorityId;
    type AuthorityIdOfBabe = pallet_ocw::sr25519_babe::AuthorityId;
    type GracePeriod = GracePeriod;
    type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
}

// TODO::发送具签名交易时所具备的信息
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

        // TODO::给自己的一个数据做签名，签名后的数据叫做 raw_payload
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = Indices::unlookup(account);
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
use super::*;
use pallet_ocw;
use frame_support::traits::FindAuthor;
use frame_support::ConsensusEngineId;

// An index to a block.
pub type BlockNumber = u32;

parameter_types! {
	// pub const PriceVecMaxSize: u32 = 50;
    // pub const MaxCountOfPerRequest: u8 = 2;
	// pub const UnsignedInterval: u32 = 10;
	pub const UnsignedPriority: u64 = 1 << 20;
    pub const NeedVerifierCheck: bool = true;
    pub const UseOnChainPriceRequest: bool = true;
    pub const FractionLengthNum: u32 = 2;
    pub const CalculationKind: u8 = 1;
}

impl pallet_ocw::Config for Runtime {
    type Event = Event;
    type Call = Call;
    type AuthorityId = pallet_ocw::crypto::OcwAuthId ;
    type AuthorityAres = pallet_ocw::sr25519::AuthorityId;
    // type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;

    // TODO:: will be remove
    // type ValidatorSet = Historical;

    // type FindAuthor = staking_extend::OcwFindAuthor<Babe, Self> ; // OcwFindAuthor<Babe>;// Babe;
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self,Babe>;

    // type PriceVecMaxSize = PriceVecMaxSize;
    // type MaxCountOfPerRequest = MaxCountOfPerRequest;
    type NeedVerifierCheck = NeedVerifierCheck;
    type UseOnChainPriceRequest = UseOnChainPriceRequest;
    type FractionLengthNum = FractionLengthNum;
    type CalculationKind = CalculationKind;
    type RequestOrigin = pallet_collective::EnsureProportionAtLeast<_1, _2, AccountId, TechnicalCollective> ; // frame_system::EnsureRoot<AccountId>;

    // type MemberAuthority = sp_consensus_babe::AuthorityId ;
    // type Member = Babe;

    type ValidatorAuthority = <Self as frame_system::Config>::AccountId;
    type VMember = StakingExtend;
    // type VMember = MemberExtend;

}

// const TEST_ID: ConsensusEngineId = [1, 2, 3, 4];
// pub struct OcwFindAuthor<Inner>(sp_std::marker::PhantomData<Inner>);
// impl <Inner: FindAuthor<u32>> FindAuthor<u32> for OcwFindAuthor<Inner> {
//     fn find_author<'a, I>(digests: I) -> Option<u32> where
//         I: 'a + IntoIterator<Item=(ConsensusEngineId, &'a [u8])>
//     {
//         log::info!("RUN OcwFindAuthor<Inner> = Bebing.");
//         let author_index =  Inner::find_author(digests);
//         log::info!("RUN OcwFindAuthor<Inner> = Value = {:?} ", author_index);
//         author_index
//         // for (id, data) in digests {
//         //     if id == TEST_ID {
//         //         return AccountId::decode(&mut &data[..]).ok();
//         //     }
//         // }
//         // None
//     }
// }

// pub struct FindAccountFromAuthorIndex<T, Inner>(sp_std::marker::PhantomData<(T, Inner)>);
// impl<T: Config, Inner: FindAuthor<u32>> FindAuthor<T::ValidatorId>
// for FindAccountFromAuthorIndex<T, Inner>
// {
//     // fn find_author<'a, I>(digests: I) -> Option<T::ValidatorId>
//     //     where I: 'a + IntoIterator<Item=(ConsensusEngineId, &'a [u8])>
//     // {
//     //     let i = Inner::find_author(digests)?;
//     //
//     //     let validators = <Module<T>>::validators();
//     //     validators.get(i as usize).map(|k| k.clone())
//     // }
//
//     fn find_author<'a, I>(digests: I) -> Option<AccountId> where
//         I: 'a + IntoIterator<Item=(ConsensusEngineId, &'a [u8])>
//     {
//         for (id, data) in digests {
//             if id == TEST_ID {
//                 return AccountId::decode(&mut &data[..]).ok();
//             }
//         }
//         None
//     }
// }

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

        // TODO::Sign one of your own data, the signed data is called raw_payload
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
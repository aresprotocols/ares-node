#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::{
    self as system,
    offchain::{
        AppCrypto, CreateSignedTransaction,
        SignedPayload, SigningTypes,
    },
};

use sp_core::crypto::KeyTypeId;
use core::{fmt};
use sp_runtime::{ RuntimeDebug, offchain::{http, Duration}, transaction_validity::{InvalidTransaction, ValidTransaction, TransactionValidity}, RuntimeAppPublic, AccountId32};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
use lite_json::json::JsonValue;

use frame_support::traits::{ Get, ValidatorSet, FindAuthor};
use serde::{Deserialize, Deserializer};
use sp_std::{prelude::*, str, };
use frame_support::sp_std::str::FromStr;

#[cfg(test)]
mod tests;

/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"ares"); // sp_application_crypto::key_types::BABE ; //
pub const LOCAL_STORAGE_PRICE_REQUEST_MAKE_POOL: &[u8] = b"are-ocw::make_price_request_pool";
pub const LOCAL_STORAGE_PRICE_REQUEST_LIST: &[u8] = b"are-ocw::price_request_list";
pub const LOCAL_STORAGE_PRICE_REQUEST_DOMAIN: &[u8] = b"are-ocw::price_request_domain";
pub const CALCULATION_KIND_AVERAGE: u8 = 1;
pub const CALCULATION_KIND_MEDIAN: u8 = 2;

// #[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug)]
// pub enum PriceKey {
//     PriceKeyIsNone, // PRICE_KEY_IS_NONE,
//     PriceKeyIsBTC, // PRICE_KEY_IS_BTC,
//     PriceKeyIsETH, // PRICE_KEY_IS_ETH,
//     PriceKeyIsDOT, // PRICE_KEY_IS_DOT,
//     PriceKeyIsXRP, // PRICE_KEY_IS_XRP,
// }

/// the types with this pallet-specific identifier.
pub mod crypto {
    use super::KEY_TYPE;
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        traits::Verify,
        MultiSignature, MultiSigner,
    };
    use sp_core::sr25519::Signature as Sr25519Signature;

    app_crypto!(sr25519, KEY_TYPE);

    // struct fro production
    pub struct OcwAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for OcwAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for OcwAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}

pub mod sr25519 {
    use super::KEY_TYPE;

    mod app_sr25519 {
        use super::KEY_TYPE;
        use sp_application_crypto::{app_crypto, sr25519};
        app_crypto!(sr25519, KEY_TYPE);
    }

    sp_application_crypto::with_pair! {
		/// An i'm online keypair using sr25519 as its crypto.
		pub type AuthorityPair = app_sr25519::Pair;
	}

    /// An i'm online signature using sr25519 as its crypto.
    pub type AuthoritySignature = app_sr25519::Signature;

    /// An i'm online identifier using sr25519 as its crypto.
    pub type AuthorityId = app_sr25519::Public;
}

pub use pallet::*;
use frame_system::offchain::{Signer, SendUnsignedTransaction};
use sp_runtime::offchain::storage::StorageValueRef;
use sp_runtime::offchain::storage_lock::{BlockAndTime, StorageLock};
use lite_json::NumberValue;


type FractionLength = u32;
type RequestInterval = u8;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use super::*;
    use frame_support::sp_runtime::traits::{IdentifyAccount, IsMember};
    use sp_core::crypto::UncheckedFrom;
    use frame_support::sp_std::convert::TryInto;

    #[pallet::error]
    pub enum Error<T> {
        ///
        UnknownAresPriceVersionNum,
    }

    /// This pallet's configuration trait
    #[pallet::config]
    pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config
        where sp_runtime::AccountId32: From<<Self as frame_system::Config>::AccountId>,
              u64: From<<Self as frame_system::Config>::BlockNumber>
    {
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// The overarching dispatch call type.
        type Call: From<Call<Self>>;

        /// ocw store key pair.
        type AuthorityAres: Member + Parameter + RuntimeAppPublic + Default + Ord + MaybeSerializeDeserialize + UncheckedFrom<[u8; 32]>;

        /// A type for retrieving the validators supposed to be online in a session.
        // type ValidatorSet: ValidatorSet<Self::AccountId> ;

        type FindAuthor: FindAuthor<Self::AccountId>;

        // type MemberAuthority: Member + Parameter + RuntimeAppPublic + Default + Ord + MaybeSerializeDeserialize + UncheckedFrom<[u8; 32]>;
        // type Member: IsMember<Self::MemberAuthority>;

        type ValidatorAuthority : IsType<<Self as frame_system::Config>::AccountId> + Member;
        type VMember : IsMember<Self::ValidatorAuthority>;

        /// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
        // #[pallet::constant]
        // type UnsignedInterval: Get<Self::BlockNumber>;
        //
        // /// A configuration for base priority of unsigned transactions.
        // ///
        // /// This is exposed so that it can be tuned for particular runtime, when
        // /// multiple pallets send unsigned transactions.
        #[pallet::constant]
        type UnsignedPriority: Get<TransactionPriority>;

        // // A configuration for PricePayload::price size.
        // // TODO:: will be del.
        // #[pallet::constant]
        // type PriceVecMaxSize: Get<u32>;

        // #[pallet::constant]
        // type MaxCountOfPerRequest: Get<u8>;

        #[pallet::constant]
        type NeedVerifierCheck: Get<bool>;

        #[pallet::constant]
        type UseOnChainPriceRequest: Get<bool>;

        // Used to confirm RequestPropose.
        type RequestOrigin: EnsureOrigin<Self::Origin>;

        #[pallet::constant]
        type FractionLengthNum: Get<u32>;

        #[pallet::constant]
        type CalculationKind: Get<u8>;

    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        /// You can use `Local Storage` API to coordinate runs of the worker.
        fn offchain_worker(block_number: T::BlockNumber) {

            let block_author = Self::get_block_author();

            // let validators = T::ValidatorSet::validators();
            // let author_info = &validators[author as usize];
            // log::info!("author info == {:?}", author_info);

            // let test_author :T::AccountId = <pallet_authorship::Pallet<T>>::author();

            // log::info!(" ======AA======= LIN DEBUG:: offchain_worker , author = {:?}", &test_author);
            // let encode_data: Vec<u8> = test_author.encode();
            // // let encode_data: Vec<u8> = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".encode();
            // assert!(32 == encode_data.len());
            // // println!("encode_data = {:?}", encode_data);
            // let raw: Result<[u8; 32], _> = encode_data.try_into();
            // let raw_data = raw.unwrap();
            // //
            // let member_authority = T::MemberAuthority::unchecked_from(raw_data);
            // log::info!(" ======AA======= LIN DEBUG:: offchain_worker , member_authority = {:?}", &member_authority);
            // // --
            // let is_member = T::Member::is_member(&member_authority);
            // log::info!("======AA====== LIN DEBUG:: T::Member::is_member = {:?} ", &is_member);

            // let test_author:T::ValidatorAuthority = test_author.into();
            // let is_member = T::VMember::is_member(&test_author);
            // log::info!("======BB====== LIN DEBUG:: T::Member::is_member = {:?} ", &is_member);



            // let raw: Result<[u8; 32], _> = encode_data.try_into();
            // if(raw.is_err()) {
            //     // --- error
            // }
            // let author = T::MemberAuthority::unchecked_from(raw);
            // let is_author = T::Member::is_member(&author);

            match block_author {
                None => { log::warn!(" Warn!!! not found author."); }
                Some(author) => {
                    log::info!("Ares price worker author {:?} ", &author);
                    // if Self::are_block_author_and_sotre_key_the_same(<pallet_authorship::Pallet<T>>::author()) {
                    if Self::are_block_author_and_sotre_key_the_same(author) {
                        // Try to get ares price.
                        match Self::ares_price_worker(block_number) {
                            Ok(v) => log::info!("Ares price at work : {:?} ", v),
                            Err(e) => log::warn!("ERROR:: Ares price has a problem : {:?}", e),
                        }
                    }
                }
            }

            // // TODO:: develop Offchain request loading.
            // Self::fetch_local_price_request_info();

            // TODO:: for debug info
            // if let (_, price_request_vec) = Self::get_local_storage_price_request_list() {
            //     log::info!("Local price request list: {:?}", price_request_vec);
            // }

        }
    }

    /// A public part of the pallet.
    #[pallet::call]
    impl<T: Config> Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {

        #[pallet::weight(0)]
        pub fn submit_price_unsigned_with_signed_payload(
            origin: OriginFor<T>,
            price_payload: PricePayload< T::Public, T::BlockNumber>,
            _signature: T::Signature
        ) -> DispatchResultWithPostInfo {

            // This ensures that the function can only be called via unsigned transaction.
            ensure_none(origin)?;

            // Nodes with the right to increase prices
            let price_list = price_payload.price; // price_list: Vec<(PriceKey, u32)>,

            let mut event_result: Vec<(Vec<u8>, u64, FractionLength)> = Vec::new();
            for (price_key, price,fraction_length, json_number_value) in price_list.clone() {
                // Add the price to the on-chain list, but mark it as coming from an empty address.
                // log::info!(" Call add_price {:?}", sp_std::str::from_utf8(&price_key));
                Self::add_price(price_payload.public.clone().into_account(), price.clone(), price_key.clone(), fraction_length, json_number_value, Self::get_price_pool_depth());
                event_result.push((price_key, price, fraction_length));
            }

            // // TODO:: will be remove.
            // log::info!("Call try to send Event {:?}", &event_result);
            // Self::deposit_event(Event::KittyCreate(who, kitty_id));
            Self::deposit_event(Event::NewPrice(event_result, price_payload.public.clone().into_account()));
            // Self::deposit_event(Event::NewPrice(price_list , price_payload.public.clone().into_account()));

            // now increment the block number at which we expect next unsigned transaction.
            // let current_block = <system::Pallet<T>>::block_number();
            // <NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());

            Ok(().into())
        }

        #[pallet::weight(0)]
        pub fn revoke_request_propose(origin: OriginFor<T>, price_key: Vec<u8>) -> DispatchResult {
            T::RequestOrigin::ensure_origin(origin)?;

            <PricesRequests<T>>::mutate(| prices_request| {
                for (index, (old_price_key,_,_,_,_)) in prices_request.clone().into_iter().enumerate() {
                    if &price_key == &old_price_key {
                        // remove old one
                        prices_request.remove(index);
                        // <AresPrice<T>>::remove(&price_key);
                        // <AresAvgPrice<T>>::remove(&price_key);
                        Self::clear_price_storage_data(price_key.clone());
                        break;
                    }
                }
            });

            Self::deposit_event(Event::RevokePriceRequest(price_key));

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn request_propose(origin: OriginFor<T>, price_key: Vec<u8>, request_url: Vec<u8>, parse_version: u32, fraction_num: FractionLength, request_interval: RequestInterval) -> DispatchResult {
            T::RequestOrigin::ensure_origin(origin)?;

            // Search exists
            // let old_data = <PricesRequests<T>>::get().into_iter().all(|(old_price_key,_,_,_)|{ price_key == old_price_key });

            <PricesRequests<T>>::mutate(| prices_request| {
                let mut find_old = false;
                for (index, (old_price_key,
                    _old_request_url,
                    _old_parse_version,
                    old_fraction_count,_)) in prices_request.clone().into_iter().enumerate() {
                    if &price_key == &old_price_key {

                        if &"".as_bytes().to_vec() != &request_url {
                            // add input value
                            prices_request.push((price_key.clone(), request_url.clone(), parse_version, fraction_num.clone(), request_interval.clone()));
                            Self::deposit_event(Event::UpdatePriceRequest(price_key.clone(), request_url.clone(), parse_version.clone(), fraction_num.clone()));
                        }

                        // remove old one
                        prices_request.remove(index);

                        // check fraction number on change
                        if &old_fraction_count != &fraction_num || &"".as_bytes().to_vec() == &request_url {
                            if <AresPrice<T>>::contains_key(&price_key) {
                                // if exists will be empty
                                <AresPrice<T>>::remove(&price_key);
                            }
                            // remove avg
                            if <AresAvgPrice<T>>::contains_key(&price_key) {
                                // if exists will be empty
                                <AresAvgPrice<T>>::remove(&price_key);
                            }
                        }

                        // then break for.
                        find_old = true;
                        break;
                    }
                }
                if !find_old {
                    prices_request.push((price_key.clone(), request_url.clone(), parse_version.clone(), fraction_num.clone(), request_interval.clone()));
                    Self::deposit_event(Event::AddPriceRequest(price_key, request_url, parse_version, fraction_num));
                }
            });

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn allowable_offset_propose(origin: OriginFor<T>, offset: u8) -> DispatchResult {
            T::RequestOrigin::ensure_origin(origin)?;
            <PriceAllowableOffset<T>>::put(offset);
            Self::deposit_event(Event::PriceAllowableOffsetUpdate(offset));

            Ok(())
        }

        #[pallet::weight(0)]
        pub fn pool_depth_propose(origin: OriginFor<T>, depth: u32) -> DispatchResult {
            T::RequestOrigin::ensure_origin(origin)?;
            // Judge the value must be greater than 0 and less than the maximum of U32
            assert!( depth > 0 && depth < u32::MAX, "Depth wrong value range.");

            // get old depth number
            let old_depth = <PricePoolDepth<T>>::get();

            assert_ne!(old_depth, depth, "Depth of change cannot be the same.");

            <PricePoolDepth<T>>::set(depth.clone());
            Self::deposit_event(Event::PricePoolDepthUpdate(depth));

            if depth > old_depth {
                // <PricesRequests<T>>::get().into_iter().any(|(price_key,_,_,_,_)|{
                //     // clear average.
                //     <AresAvgPrice<T>>::remove(&price_key);
                //     false
                // }) ;
            }else {
                <PricesRequests<T>>::get().into_iter().any(|(price_key,_,_,_,_)|{

                    // clear average.
                    let old_price_list = <AresPrice<T>>::get(price_key.clone());
                    let depth_usize =  depth as usize;
                    // check length
                    if old_price_list.len() > depth_usize {
                        let diff_len = old_price_list.len() - depth_usize;
                        let mut new_price_list = Vec::new();
                        for (index, value) in old_price_list.into_iter().enumerate() {
                            if !(index < diff_len) {
                                // kick out old value.
                                new_price_list.push(value);
                            }
                        }

                        // Reduce the depth.
                        <AresPrice<T>>::insert(price_key.clone(), new_price_list);
                    }
                    // need to recalculate the average.
                    Self::check_and_update_avg_price_storage(price_key, depth);
                    false
                }) ;
            }
            Ok(())
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        // (price_key, price_val, fraction len)
        NewPrice(Vec<(Vec<u8>, u64, FractionLength)>, T::AccountId),
        // Average price update.
        RevokePriceRequest(Vec<u8>),
        AddPriceRequest(Vec<u8>, Vec<u8>, u32, FractionLength),
        UpdatePriceRequest(Vec<u8>, Vec<u8>, u32, FractionLength),
        //
        PricePoolDepthUpdate(u32),
        //
        PriceAllowableOffsetUpdate(u8),
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>,
              // <T as frame_system::Config>::AccountId: From<<<T as pallet::Config>::ValidatorSet as frame_support::traits::ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>,
    {
        type Call = Call<T>;


        fn validate_unsigned(
            _source: TransactionSource,
            call: &Self::Call,
        ) -> TransactionValidity
        {
            if let Call::submit_price_unsigned_with_signed_payload(
                ref payload, ref signature,
            ) = call {

                // log::info!("RUN ==================== 1");
                // let worker_ownerid_list = T::AuthorityAres::all();
                // log::info!("RUN ==================== 2");

                // TODO::----------- check need this. begin
                // Get all validators.
                // let current_validators = T::ValidatorSet::validators();
                //
                // // Check Signer in validator group.
                // let mut find_validator = !T::NeedVerifierCheck::get() ; // Self::get_default_find_validator_bool();
                // for validator in current_validators {
                //     log::info!("=============== Loop {:?} Signer {:?}", validator.clone(), payload.public.clone() );
                //     let account : T::AccountId = <T as SigningTypes>::Public::into_account( payload.public.clone());
                //     let validator_account : T::AccountId = validator.into();
                //     log::info!("=============== account {:?} validator_account {:?}", account.clone(), validator_account.clone() );
                //     if account == validator_account {
                //         find_validator = true;
                //     }
                // }

                let mut find_validator = !T::NeedVerifierCheck::get() ;
                if false == find_validator {
                    // check exists
                    // let encode_data: Vec<u8> = payload.public.encode();
                    let validator_authority:T::ValidatorAuthority = <T as SigningTypes>::Public::into_account( payload.public.clone()).into();
                    find_validator = T::VMember::is_member(&validator_authority);
                }

                if !find_validator {
                    log::info!(" ===== InvalidTransaction::BadProof =====");
                    return InvalidTransaction::BadProof.into();
                }

                // let payload_account : T::AccountId = <T as SigningTypes>::Public::into_account( payload.public.clone());
                // log::info!(" payload_account = {:?} ", payload_account);
                // if !Self::are_block_author_and_sotre_key_the_same(payload_account) {
                //     return InvalidTransaction::BadProof.into();
                // }

                let signature_valid = SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
                if !signature_valid {
                    return InvalidTransaction::BadProof.into();
                }
                Self::validate_transaction_parameters_of_ares(&payload.block_number, payload.price.to_vec())
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }

    // #[pallet::storage]
    // #[pallet::getter(fn next_unsigned_at)]
    // pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    /// A vector of recently submitted prices.
    #[pallet::storage]
    #[pallet::getter(fn prices_trace)]
    pub(super) type PricesTrace<T: Config> = StorageValue<_, Vec<(u64, T::AccountId, T::AccountId)>, ValueQuery>;

    /// The lookup table for names.
    #[pallet::storage]
    #[pallet::getter(fn ares_prices)]
    pub(super) type AresPrice<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,
        // price, account, bolcknumber, FractionLength, JsonNumberValue
        Vec<(u64, T::AccountId, T::BlockNumber, FractionLength, JsonNumberValue)>,
        // Vec<(u64, T::AccountId)>,
        ValueQuery
    >;

    /// The lookup table for names.
    #[pallet::storage]
    #[pallet::getter(fn ares_abnormal_prices)]
    pub(super) type AresAbnormalPrice<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,
        // price, account, bolcknumber, FractionLength, JsonNumberValue
        Vec<(u64, T::AccountId, T::BlockNumber, FractionLength, JsonNumberValue)>,
        // Vec<(u64, T::AccountId)>,
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn ares_avg_prices)]
    pub(super) type AresAvgPrice<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,
        // price
        (u64, FractionLength),
        ValueQuery
    >;


    #[pallet::storage]
    #[pallet::getter(fn price_pool_depth)]
    pub(super) type PricePoolDepth<T: Config> = StorageValue<
        _,
        u32,
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn price_allowable_offset)]
    pub(super) type PriceAllowableOffset<T: Config> = StorageValue<
        _,
        u8,
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn prices_requests)]
    pub(super) type PricesRequests<T: Config> = StorageValue<
        _,
        Vec<(
            Vec<u8>, // price key
            Vec<u8>, // request url
            u32, // parse version number.
            FractionLength,
            RequestInterval,
        )>,
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn request_base_onchain)]
    pub(super) type RequestBaseOnchain<T: Config> = StorageValue<
        _,
        Vec<u8>,
        ValueQuery
    >;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config>
        where AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        pub _phantom: sp_std::marker::PhantomData<T>,
        pub request_base: Vec<u8>,
        pub price_allowable_offset: u8,
        pub price_pool_depth: u32,
        pub price_requests: Vec<(Vec<u8>, Vec<u8>, u32, FractionLength, RequestInterval )>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T>
        where AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        fn default() -> Self {
            GenesisConfig {
                _phantom: Default::default(),
                request_base: Vec::new(),
                price_allowable_offset: 10u8,
                price_pool_depth: 10u32,
                price_requests: Vec::new(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T>
        where AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        fn build(&self) {
            if !self.price_requests.is_empty() {
                PricesRequests::<T>::put(&self.price_requests);
            }
            if self.price_pool_depth > 0 {
                PricePoolDepth::<T>::put(&self.price_pool_depth);
            }
            if self.request_base.len() > 0 {
                RequestBaseOnchain::<T>::put(&self.request_base);
                // storage write
                // let mut storage_request_base = StorageValueRef::persistent(LOCAL_STORAGE_PRICE_REQUEST_DOMAIN);
                // storage_request_base.set(&self.request_base);
            }
            PriceAllowableOffset::<T>::put(self.price_allowable_offset );
        }
    }

}

// warp NumberValue
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct JsonNumberValue {
    pub integer: u64,
    pub fraction: u64,
    pub fraction_length: u32,
    pub exponent: u32,
}

//
impl JsonNumberValue {
    pub fn new(number_value: NumberValue) -> Self {
        if number_value.integer < 0 || number_value.exponent < 0 {
            panic!("Error source NumberValue integer or exponent");
        }
        Self {
            fraction_length : number_value.fraction_length,
            fraction : number_value.fraction,
            exponent : number_value.exponent as u32,
            integer : number_value.integer as u64,
        }
    }

    pub fn toPrice(&self, fraction_number: FractionLength) -> u64 {
        let mut price_fraction = self.fraction ;
        if price_fraction < 10u64.pow(fraction_number) {
            price_fraction *= 10u64.pow(fraction_number.checked_sub(self.fraction_length).unwrap_or(0));
        }
        let exp = self.fraction_length.checked_sub(fraction_number).unwrap_or(0);
        self.integer as u64 * (10u64.pow(fraction_number)) + (price_fraction / 10_u64.pow(exp))
    }
}

#[cfg(feature = "std")]
impl Default for JsonNumberValue {
    fn default() -> Self {
        Self {
            fraction_length : 0,
            fraction : 0,
            exponent : 0,
            integer : 0,
        }
    }
}

/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PricePayload<Public, BlockNumber> {
    block_number: BlockNumber,
    // price_key,price_val, fraction len
    price: Vec<(Vec<u8>, u64, FractionLength, JsonNumberValue)>,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PricePayload<T::Public, T::BlockNumber> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: Config> Pallet<T>
    where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
          u64: From<<T as frame_system::Config>::BlockNumber>,
          // <T as frame_system::Config>::AccountId: From<<<T as pallet::Config>::ValidatorSet as Trait>::ValidatorId>,
                                    // <<T as pallet::Config>::ValidatorSet as Trait>::ValidatorId`

{
    fn are_block_author_and_sotre_key_the_same(block_author: T::AccountId) -> bool {
        let mut is_same = !T::NeedVerifierCheck::get(); // Self::get_default_author_save_bool();
        let worker_ownerid_list = T::AuthorityAres::all();
        for ownerid in worker_ownerid_list.iter() {
            let mut a = [0u8; 32];
            a[..].copy_from_slice(&ownerid.to_raw_vec());
            // extract AccountId32 from store keys
            let owner_account_id32 = AccountId32::new(a);
            // get Block owner info
            // let block_author = <pallet_authorship::Pallet<T>>::author();

            // on debug!
            log::info!("Checking ... owner_account_id32 == block_author.into()");
            let test_into: AccountId32 = block_author.clone().into();
            log::info!("{:?} == {:?}", owner_account_id32.clone(), test_into);
            // debug end.
            if owner_account_id32 == block_author.clone().into() {
                is_same = true;
            }
        }
        is_same
    }

    // // Assert whether the block can be submit price.
    // fn is_submittable_block_now(block_number: T::BlockNumber) ->bool {
    //     let next_unsigned_at = <NextUnsignedAt<T>>::get();
    //     if next_unsigned_at > block_number {
    //         log::info!("Wait next_unsigned_at > block_number = {:?} > {:?}", next_unsigned_at, block_number);
    //         return false;
    //     }
    //     return true;
    // }

    /// Obtain ares price and submit it.
    fn ares_price_worker(block_number: T::BlockNumber) -> Result<(), &'static str> {
        // if !Self::is_submittable_block_now(block_number) {
        //     return Err("It's too early.");
        // }
        // let res = Self::fetch_ares_price_and_send_raw_unsigned(block_number); // PriceKey::PRICE_KEY_IS_ETH
        let res = Self::save_fetch_ares_price_and_send_payload_signed(block_number); // PriceKey::PRICE_KEY_IS_ETH
        if let Err(e) = res {
            log::error!("ERROR:: fetch_ares_price_and_send_raw_unsigned on offchain 2: {:?}", e);
        }
        Ok(())
    }

    // get uri key raw of ARES price
    fn get_price_source_list (read_chain_data: bool) ->Vec<(Vec<u8>, Vec<u8>, u32, FractionLength, RequestInterval)> {
        // Use the on chain storage data mode.
        if read_chain_data {
            let result:Vec<(Vec<u8>, Vec<u8>, u32, FractionLength, RequestInterval)> = <PricesRequests<T>>::get().into_iter().map(|(price_key,request_url,parse_version,fraction_length, request_interval)|{
                (
                    price_key,
                    // sp_std::str::from_utf8(&request_url).unwrap().clone(),
                    Self::make_local_storage_request_uri_by_vec_u8(request_url),
                    parse_version,
                    fraction_length,
                    request_interval,
                )
            }).collect() ;
            return result;
        }

        Vec::new()
    }

    // get uri key raw of ARES price
    fn get_raw_price_source_list (read_chain_data: bool)->Vec<(Vec<u8>, Vec<u8>, u32, FractionLength, RequestInterval)>{
        // Use the on chain storage data mode.
        if read_chain_data {
            let result:Vec<(Vec<u8>, Vec<u8>, u32, FractionLength, RequestInterval)> = <PricesRequests<T>>::get().into_iter().map(|(price_key,request_url,parse_version,fraction_length, request_interval)|{
                (
                    price_key,
                    // sp_std::str::from_utf8(&request_url).unwrap().clone(),
                    request_url,
                    parse_version,
                    fraction_length,
                    request_interval,
                )
            }).collect() ;
            return result;
        }

        Vec::new()
    }

    // Get request domain, include TCP protocol, example: http://www.xxxx.com
    fn get_local_storage_request_domain() -> Vec<u8> {

        let request_base_onchain = RequestBaseOnchain::<T>::get();
        if request_base_onchain.len() > 0  {
            return request_base_onchain;
        }

        let mut storage_request_base = StorageValueRef::persistent(LOCAL_STORAGE_PRICE_REQUEST_DOMAIN);

        if let Some(request_base) = storage_request_base
            .get::<Vec<u8>>()
            .unwrap_or(Some(Vec::new()))
        {

            if let Ok(result_base_str) = sp_std::str::from_utf8(&request_base) {
                log::info!("Ares local request base : {:?} .", &result_base_str);
            }
            return request_base;
        } else {
            log::warn!("Not found request base url.");
        }
        // log::info!("Ares local request base : {:?} .", &result_base_str);
        Vec::new()
    }

    fn make_local_storage_request_uri_by_str(sub_path: &str) -> Vec<u8> {
        Self::make_local_storage_request_uri_by_vec_u8(sub_path.as_bytes().to_vec())
    }
    fn make_local_storage_request_uri_by_vec_u8(sub_path: Vec<u8>) -> Vec<u8> {
        let domain = Self::get_local_storage_request_domain(); //.as_bytes().to_vec();
        [domain, sub_path].concat()
    }

    fn get_block_author() -> Option<T::AccountId> {
        let digest = <frame_system::Pallet<T>>::digest();
        let pre_runtime_digests = digest.logs.iter().filter_map(|d| d.as_pre_runtime());
        <T as pallet::Config>::FindAuthor::find_author(pre_runtime_digests)
    }
    //
    // fn fetch_local_price_request_info() -> Result<(), Error<T>> {
    //
    //     // let mut make_price_request_pool = StorageValueRef::persistent(LOCAL_STORAGE_PRICE_REQUEST_MAKE_POOL);
    //     // if let Some(local_request_info) = make_price_request_pool
    //     //     .get::<Vec<u8>>()
    //     //     .unwrap_or(Some(Vec::new())) {
    //     //     log::info!("Ares local price request A: Data detected, try to parse.");
    //     //     if let Some(price_json_str) = sp_std::str::from_utf8(&local_request_info).map_err(|_| {
    //     //         log::warn!("Error:: Extracting storage format, No UTF8.");
    //     //     }).ok() {
    //     //         log::info!("Ares local price request: json data {:?}.", &price_json_str);
    //     //         // to update local price storage.
    //     //         // Self::update_local_price_storage(price_json_str);
    //     //     }
    //     //     // Clear data.
    //     //     // make_price_request_pool.clear()
    //     // }else{
    //     //     // make_price_request_pool.set(&"{\"name\":\"linhai\"}".as_bytes().to_vec()) ;
    //     //     log::info!(" Ares local price request: Waiting to insert data.");
    //     // }
    //
    //     let mut storage_request_base = StorageValueRef::persistent(LOCAL_STORAGE_PRICE_REQUEST_DOMAIN);
    //     if let Some(request_base) = storage_request_base
    //         .get::<Vec<u8>>()
    //         .unwrap_or(Some(Vec::new()))
    //     {
    //         log::info!("Ares local request base B: Data detected, try to parse.");
    //         if let Some(request_base_str) = sp_std::str::from_utf8(&request_base).map_err(|_| {
    //             log::warn!("Error:: Extracting storage format, No UTF8.");
    //         }).ok() {
    //             log::info!("Ares local request base : json data {:?}.", &request_base_str);
    //         }
    //     } else {
    //         log::warn!("Not found request base url.");
    //     }
    //
    //     Ok(())
    // }

    // // TODO::Will be delete.
    // fn get_local_storage_price_request_list() -> (StorageValueRef<'static>, Vec<LocalPriceRequestStorage>) {
    //     let price_request_local_storage = StorageValueRef::persistent(LOCAL_STORAGE_PRICE_REQUEST_LIST);
    //     if let Some(mut price_request_vec) = price_request_local_storage.get::<Vec<LocalPriceRequestStorage>>().unwrap_or(Some(Vec::new())) {
    //         return (price_request_local_storage, price_request_vec);
    //     }
    //     (price_request_local_storage, Vec::new())
    // }

    // // TODO::Will be delete.
    // fn update_local_price_storage(price_json_str: &str) -> Result<Vec<LocalPriceRequestStorage>, ()> {
    //
    //     if let Some(new_price_request) = Self::extract_local_price_storage(price_json_str) {
    //
    //         if let (price_request_local_storage, mut price_request_vec) = Self::get_local_storage_price_request_list() {
    //             if price_request_vec.len() > 0 {
    //                 log::info!("Are local price request: OLD VALUE {:?}", &price_request_vec);
    //                 for (index, local_price_request) in price_request_vec.clone().into_iter().enumerate() {
    //                     if &new_price_request.price_key == &local_price_request.price_key {
    //                         // kick out old value.
    //                         price_request_vec.remove(index);
    //                     }
    //                 }
    //                 // If not remove.
    //                 if new_price_request.request_url != "".as_bytes().to_vec() {
    //                     // Insert new request to storage
    //                     price_request_vec.push(new_price_request);
    //                 }
    //                 // Save new request list.
    //                 price_request_local_storage.set(&price_request_vec);
    //                 return Ok(price_request_vec);
    //             }else{
    //                 // create local store
    //                 let mut new_storage: Vec<LocalPriceRequestStorage> = Vec::new();
    //                 new_storage.push(new_price_request);
    //                 price_request_local_storage.set(&new_storage);
    //                 return Ok(new_storage);
    //             }
    //         }
    //     }
    //     Err(())
    // }

    // extract LocalPriceRequestStorage struct from json str
    fn extract_local_price_storage(price_json_str: &str) -> Option<LocalPriceRequestStorage> {
        serde_json::from_str(price_json_str).ok()
    }

    // Get the number of cycles required to loop the array lenght.
    // If round_num = 0 returns the maximum value of u8
    fn get_number_of_cycles(vec_len:u8, round_num:u8) -> u8 {
        if round_num == 0 {
            return u8::MAX;
        }
        let mut round_offset = 0u8;
        if vec_len % round_num != 0 {
            round_offset=1u8;
        }
        vec_len/round_num + round_offset
    }

    // Get the delimited array according to the max request num.
    // // TODO:: out of date, will be del.
    // fn get_delimited_price_source_list(source_list: Vec<(Vec<u8>, Vec<u8>, u32, u32)>, round_number: u64, max_request_count: u8) -> Vec<( Vec<u8>, Vec<u8>, u32, FractionLength)> {
    //     let vec_count = source_list.len() as u8 ;
    //
    //     let remainder_split_num = Self::get_number_of_cycles(vec_count, max_request_count);
    //     if remainder_split_num <= 0 {
    //         return Vec::new();
    //     }
    //
    //     let remainder : u64 =  (round_number % remainder_split_num as u64).into();
    //     let begin_index = remainder * max_request_count as u64;
    //     let mut end_index = begin_index + max_request_count as u64;
    //     if end_index > source_list.len() as u64 {
    //         end_index = source_list.len() as u64;
    //     }
    //
    //     source_list[begin_index as usize .. end_index as usize].to_vec()
    // }

    fn save_fetch_ares_price_and_send_payload_signed(block_number: T::BlockNumber) -> Result<(), &'static str> {


        // let price_source_list = Self::get_delimited_price_source_list(Self::get_price_source_list(T::UseOnChainPriceRequest::get()), block_number.into(), max_request_count);
        let mut price_list = Vec::new();

        // for (price_key, request_url, version_num, fraction_length) in price_source_list {
        //
        //     if let Ok(price) = Self::fetch_price_body_with_http(price_key.clone(), sp_std::str::from_utf8(&request_url).unwrap(), version_num, fraction_length) {
        //         // add price to price_list
        //         price_list.push((price_key, price, fraction_length));
        //     }
        // }

        let price_result = Self::fetch_bulk_price_with_http(block_number, 2).ok().unwrap();
        for (price_key, price_option, fraction_length , json_number_value) in price_result {
            if price_option.is_some() {
                // record price to vec!
                price_list.push((price_key, price_option.unwrap(), fraction_length, JsonNumberValue::new(json_number_value)));
            }
        }

        log::info!(" %%%%%%%%%% Price list : {:?}", price_list.clone());

        if price_list.len() > 0 {
            // -- Sign using any account
            let (_, result) = Signer::<T, T::AuthorityId>::any_account().send_unsigned_transaction(
                |account| PricePayload {
                    price: price_list.clone(),
                    block_number,
                    public: account.public.clone()
                },
                |payload, signature| {
                    Call::submit_price_unsigned_with_signed_payload(payload, signature)
                }
            ).ok_or("+++++++++ No local accounts accounts available, storekey needs to be set.")?;
            result.map_err(|()| "+++++++++ Unable to submit transaction")?;
        }
        Ok(())
    }

    //
    fn make_bulk_price_request_url(format: Vec<(Vec<u8>, Vec<u8>, FractionLength)>) -> Vec<u8> {
        // "http://141.164.58.241:5566/api/getBulkPrices".as_bytes().to_vec()
        let raw_request_url = Self::make_local_storage_request_uri_by_vec_u8("/api/getBulkPrices".as_bytes().to_vec());
        let mut request_url = Vec::new();
        for (_, extract_key, _ ) in format {
            if request_url.len() == 0 {
                request_url = [raw_request_url.clone(), "?symbol=".as_bytes().to_vec() , extract_key].concat();
            }else {
                request_url = [request_url, "_".as_bytes().to_vec(), extract_key].concat();
            }
        }
        request_url
    }

    // Make bulk request format array.
    fn make_bulk_price_format_data(block_number: T::BlockNumber) -> Vec<(Vec<u8>, Vec<u8>, FractionLength)> {
        // let FRACTION_NUM_2:u32 = 2 ;
        // let FRACTION_NUM_3:u32 = 3 ;
        // let FRACTION_NUM_4:u32 = 4 ;
        // let FRACTION_NUM_5:u32 = 5 ;
        // // Bulk parse
        // // defined parse format
        // let mut format = Vec::new();
        // format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), FRACTION_NUM_2));
        // format.push(("eth_price".as_bytes().to_vec(), "ethusdt".as_bytes().to_vec(), FRACTION_NUM_3));
        // format.push(("dot_price".as_bytes().to_vec(), "dotusdt".as_bytes().to_vec(), FRACTION_NUM_4));
        // format.push(("xrp_price".as_bytes().to_vec(), "xrpusdt".as_bytes().to_vec(), FRACTION_NUM_5));
        //
        // format

        let mut format = Vec::new();
        // let mut debug_arr: Vec<(&str,&str,u32)> = Vec::new();
        // price_key, request_url, parse_version, fraction_length
        let source_list = Self::get_raw_price_source_list(T::UseOnChainPriceRequest::get());
        // if request is '/api/getBulkPrices'
        // source_list.into_iter().map(|(price_key, request_url, parse_version, fraction_length)| {
        //
        // })

        log::info!("LIN::DEBUG A::source_list length = {:?}", source_list.len());

        // In the new version, it is more important to control the request interval here.
        for (price_key, extract_key, parse_version, fraction_length, request_interval) in source_list {
            if 2 == parse_version {
                let round_number: u64 = block_number.into();
                let remainder : u64 =  (round_number % request_interval as u64).into();
                if 0 == remainder {
                    let debug_price_key = price_key.clone();
                    // let debug_extract_key = price_key.clone();
                    // debug_arr.push((sp_std::str::from_utf8(&debug_price_key), sp_std::str::from_utf8(&debug_extract_key), fraction_length.clone()));
                    log::info!(" LIN::DEBUG B:: BN= {:?} request_interval = {:?} , key = {:?}", request_interval, block_number, sp_std::str::from_utf8(&debug_price_key));
                    format.push((price_key, extract_key, fraction_length));

                }
            }
        }
        log::info!("Ares will be request list :: {:?}", format.clone());
        format
    }

    //
    fn fetch_bulk_price_with_http(block_number: T::BlockNumber, version_num: u8) ->  Result<Vec<(Vec<u8>, Option<u64>, FractionLength, NumberValue)>, http::Error> {
        // Get current available price list.
        let format_arr = Self::make_bulk_price_format_data(block_number);
        // make request url
        let request_url = Self::make_bulk_price_request_url(format_arr.clone());
        let request_url = sp_std::str::from_utf8(&request_url).unwrap();

        // request and return http body.
        if "" == request_url {
            log::info!("Waiting for price request ... ");
            return Ok(Vec::new());
            // return Err(http::Error::Unknown);
        }
        log::info!("Go to bulk fetch_price_of_ares on http. request is : {:?}", request_url);
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(4_000));
        let request = http::Request::get(
            request_url.clone()
        );
        let pending = request
            .deadline(deadline)
            .send()
            .map_err(|_| http::Error::IoError)?;
        let response = pending.try_wait(deadline)
            .map_err(|e| {
                log::warn!("ERROR:: The network cannot connect. http::Error::DeadlineReached == {:?} ", e);
                http::Error::DeadlineReached
            })??;
        if response.code != 200 {
            log::warn!("ERROR:: Unexpected status code: {}", response.code);
            return Err(http::Error::Unknown);
        }
        let body = response.body().collect::<Vec<u8>>();
        // Create a str slice from the body.
        let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
            log::warn!("Error:: Extracting body, No UTF8 body");
            http::Error::Unknown
        })?;
        Ok(Self::bulk_parse_price_of_ares(body_str, format_arr))
    }

    /// Fetch current price and return the result in cents.
    fn fetch_price_body_with_http(_price_key: Vec<u8>, request_url: &str, version_num: u32, fraction_length: FractionLength) -> Result<u64, http::Error> {

        if "" == request_url {
            log::warn!("ERROR:: Cannot match area pricer url. ");
            return Err(http::Error::Unknown);
        }

        log::info!("Go to fetch_price_of_ares on http.");

        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(4_000));
        let request = http::Request::get(
            request_url.clone()
        );
        let pending = request
            .deadline(deadline)
            .send()
            .map_err(|_| http::Error::IoError)?;
        let response = pending.try_wait(deadline)
            .map_err(|e| {
                log::warn!("ERROR:: The network cannot connect. http::Error::DeadlineReached == {:?} ", e);
                http::Error::DeadlineReached
            })??;
        log::info!("The http server has returned a message.");
        // Let's check the status code before we proceed to reading the response.
        if response.code != 200 {
            log::warn!("ERROR:: Unexpected status code: {}", response.code);
            return Err(http::Error::Unknown);
        }
        let body = response.body().collect::<Vec<u8>>();
        // Create a str slice from the body.
        let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
            log::warn!("Error:: Extracting body, No UTF8 body");
            http::Error::Unknown
        })?;

        log::info!("Parse ares json format.");
        match version_num {
            1 => {
                let price = match Self::parse_price_of_ares(body_str, fraction_length) {
                    Some(price) => Ok(price),
                    None => {
                        log::warn!("Unable to extract price from the response: {:?}", body_str);
                        Err(http::Error::Unknown)
                    }
                }?;
                log::info!("Get the price {:?} provided by Ares", price);
                Ok(price)
            },
            _ => {
                Err(http::Error::Unknown)
            }
        }
    }

    // handler for bulk_parse_price_of_ares
    fn extract_bulk_price_by_json_value ( json_val : JsonValue, find_key: &str, param_length: FractionLength) -> Option<(u64, NumberValue)> {

        assert!(param_length <= 6, "Fraction length must be less than or equal to 6");

        let price_value = match json_val {
            JsonValue::Object(obj) => {
                // TODO:: need test again.
                let find_result = obj.into_iter().find(|(k, _)| {
                    // let tmp_k = k.iter().copied();
                    k.iter().copied().eq(find_key.chars())
                });

                match find_result {
                    None => { return None; }
                    Some((_, sub_val)) => {
                        match sub_val {
                            JsonValue::Object(price_obj) => {
                                let (_, price) = price_obj.into_iter().find(|(k, _)| {
                                    // println!("find(k) B = {:?}", k);
                                    // let tmp_k = k.iter().copied();
                                    k.iter().copied().eq("price".chars())
                                }).unwrap();
                                // println!("price = {:?}", price);
                                match price {
                                    JsonValue::Number(number) => number,
                                    _ => return None,
                                }
                            }
                            _ => { return None; }
                        }
                    }
                }
            }
            _ => { return None; }
        };

        // Make u64 with fraction length
        // let result_price = Self::format_price_fraction_to_u64(price_value.clone(), param_length);
        log::info!(" TO=DEBUG:: price::");
        let result_price = JsonNumberValue::new(price_value.clone()).toPrice(param_length);

        // A price of 0 means that the correct result of the data is not obtained.
        if result_price == 0 {
            return None;
        }
        Some((result_price, price_value))
    }

    /// format: ()
    fn bulk_parse_price_of_ares( price_str: &str, format: Vec<(Vec<u8>, Vec<u8>, FractionLength)> ) -> Vec<(Vec<u8>, Option<u64>, FractionLength, NumberValue)> {
        let val = lite_json::parse_json(price_str);

        let mut result_vec = Vec::new();
        match val.ok() {
            None => { return Vec::new(); }
            Some(obj) => {
                match obj {
                    JsonValue::Object(obj) => {
                        // find code root.
                        let (_, v_data) = obj.into_iter()
                            .find(|(k, _)| {
                                let _tmp_k = k.iter().copied();
                                k.iter().copied().eq("data".chars())
                            }).unwrap();
                        // println!("v_data = {:?}", v_data);

                        for (price_key, extract_key, fraction_length) in format {
                            let extract_key = sp_std::str::from_utf8(&extract_key).unwrap();
                            let extract_price_grp = Self::extract_bulk_price_by_json_value(v_data.clone(), extract_key, fraction_length);
                            // println!(" extract_price = {:?}", extract_price);
                            if extract_price_grp.is_some() {
                                let (extract_price, json_number_value) = extract_price_grp.unwrap();
                                // TODO::need recheck why use Some(extract_price)
                                result_vec.push((price_key, Some(extract_price), fraction_length, json_number_value));
                            }
                        }
                    },
                    _ => return Vec::new(),
                }
            }
        }

        result_vec
    }

    fn parse_price_of_ares(price_str: &str, param_length: FractionLength) -> Option<u64> {

        assert!(param_length <= 6, "Fraction length must be less than or equal to 6");

        let val = lite_json::parse_json(price_str);
        let price = match val.ok()? {
            JsonValue::Object(obj) => {
                // find code root.
                let (_, v_data) = obj.into_iter()
                    .find(|(k, _)| {
                        let _tmp_k = k.iter().copied();
                        k.iter().copied().eq("data".chars())
                    })?;

                // find price value
                match v_data {
                    JsonValue::Object(obj) => {
                        let (_, v) = obj.into_iter().find(|(k, _)| {
                            // let tmp_k = k.iter().copied();
                            k.iter().copied().eq("price".chars())
                        })?;

                        match v {
                            JsonValue::Number(number) => number,
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };
        // Some(Self::format_price_fraction_to_u64(price, param_length))
        Some(JsonNumberValue::new(price).toPrice(param_length))
    }

    // This function will to be remove. replace it JsonNumberValue toPrice()
    // fn format_price_fraction_to_u64 ( json_number: NumberValue, param_length: FractionLength) -> u64 {
    //     let mut price_fraction = json_number.fraction ;
    //     if price_fraction < 10u64.pow(param_length) {
    //         price_fraction *= 10u64.pow(param_length.checked_sub(json_number.fraction_length).unwrap_or(0));
    //     }
    //     let exp = json_number.fraction_length.checked_sub(param_length).unwrap_or(0);
    //     json_number.integer as u64 * (10u64.pow(param_length)) + (price_fraction / 10_u64.pow(exp))
    // }

    // Get price pool size
    fn get_price_pool_depth () ->u32 {
        // T::PriceVecMaxSize::get()
        <PricePoolDepth<T>>::get()
    }

    //
    fn add_price(who: T::AccountId, price:u64, price_key: Vec<u8>, fraction_length: FractionLength, json_number_value: JsonNumberValue, max_len:u32 ) {
        // println!("add_price == {:?}", price);
        let key_str = price_key;
        let current_block = <system::Pallet<T>>::block_number();
        // 1. Check key exists
        if <AresPrice<T>>::contains_key(key_str.clone()) {
            // get and reset .
            let mut old_price = <AresPrice<T>>::get(key_str.clone());
            let mut is_fraction_changed = false;
            // check fraction length inconsistent.
            for (index, (_, _, _, check_fraction, old_json_number_val)) in old_price.clone().iter().enumerate() {
                if check_fraction != &fraction_length {
                    // TODO:: Instead new funciton. !
                    // old_price.clear();
                    is_fraction_changed = true;
                    break;
                }
            }

            //
            let mut new_price = Vec::new();
            let MAX_LEN: usize = max_len.clone() as usize;

            for (index, value) in old_price.iter().enumerate() {
                if old_price.len() >= MAX_LEN && 0 == index {
                    continue;
                }

                let mut old_value = (*value).clone();
                if is_fraction_changed {
                    old_value = match (*value).clone() {
                        (old_price, account_id, b_number, old_fraction_lenght, json_number_value) => {
                            (
                                json_number_value.toPrice(fraction_length.clone()),
                                account_id,
                                b_number,
                                fraction_length.clone(),
                                json_number_value,
                            )
                        }
                    };
                }

                // let new_value = old_value;
                new_price.push(old_value);
            }

            new_price.push((price.clone(), who.clone(), current_block, fraction_length, json_number_value));
            <AresPrice<T>>::insert(key_str.clone(), new_price);
        } else {
            // push a new value.
            let mut new_price: Vec<(u64, T::AccountId, T::BlockNumber, FractionLength, JsonNumberValue)> = Vec::new();
            new_price.push((price.clone(), who.clone(), current_block, fraction_length, json_number_value));
            <AresPrice<T>>::insert(key_str.clone(), new_price);
        }

        // Get current block number for test.
        // let current_block = <system::Pallet<T>>::block_number();

        <PricesTrace<T>>::mutate(|prices_trace| {
            // let author = <pallet_authorship::Pallet<T>>::author();
            let author = Self::get_block_author().unwrap();
            let MAX_LEN: usize = max_len.clone() as usize;
            let price_trace_len = prices_trace.len();
            if price_trace_len < MAX_LEN {
                prices_trace.push((price.clone(), author.clone(), who.clone()));
            } else {
                prices_trace[price_trace_len % MAX_LEN] = (price.clone(), author.clone(), who.clone());
            }
        });

        // // Check price pool deep reaches the maximum value, and if so, calculated the average.
        // if  <AresPrice<T>>::get(key_str.clone()).len() >= max_len as usize {
        //     let average = Self::average_price(key_str.clone(), T::CalculationKind::get())
        //         .expect("The average is not empty.");
        //     log::info!("Calculate current average price average price is: ({},{}) , {:?}", average, fraction_length, &key_str);
        //     // Update avg price
        //     <AresAvgPrice<T>>::insert(key_str.clone(), (average, fraction_length));
        // }else{
        //     <AresAvgPrice<T>>::insert(key_str.clone(), (0, 0));
        // }

        // let ares_price_list_len = <AresPrice<T>>::get(key_str.clone()).len();
        // if ares_price_list_len >= max_len as usize && ares_price_list_len > 0 {
        //     println!("update_avg_price_storage price count = {:?}", ares_price_list_len);
        //     Self::update_avg_price_storage(key_str.clone(), max_len);
        // }

        Self::check_and_update_avg_price_storage(key_str.clone(), max_len);

        // Check if the price request exists, if not, clear storage data.
        let price_request_list = <PricesRequests<T>>::get();
        let has_key = price_request_list.iter().any(|(any_price, _, _, _, _)|{
            any_price == &key_str
        });
        if !has_key {
            Self::clear_price_storage_data(key_str);
        }
    }

    fn check_and_update_avg_price_storage(key_str: Vec<u8>, max_len: u32) {
        let ares_price_list_len = <AresPrice<T>>::get(key_str.clone()).len();
        if ares_price_list_len >= max_len as usize && ares_price_list_len > 0 {
            // println!("update_avg_price_storage price count = {:?}", ares_price_list_len);
            Self::update_avg_price_storage(key_str.clone(), max_len);
        }
    }

    // TODO:: remove max_len ?
    fn update_avg_price_storage(key_str: Vec<u8>, max_len: u32) {
        // Check price pool deep reaches the maximum value, and if so, calculated the average.
        // if  <AresPrice<T>>::get(key_str.clone()).len() >= max_len as usize {

            let (average,fraction_length) = Self::average_price(key_str.clone(), T::CalculationKind::get())
                .expect("The average is not empty.");
            log::info!("Calculate current average price average price is: ({},{}) , {:?}", average, fraction_length, &key_str);

            let mut price_list_of_pool = <AresPrice<T>>::get(key_str.clone());
            // Abnormal price index list
            let mut abnormal_price_index_list = Vec::new();
            // Pick abnormal price.
            if 0 < price_list_of_pool.len() {
                for (index, check_price) in price_list_of_pool.iter().enumerate() {

                    let offset_percent = match check_price.0 {
                        x if &x >  &average => {
                            // println!("A:: &x >  &average  = {:?} > {:?}", &x, &average);
                            // println!("&x /  &average  = {:?} / {:?}", ((x - average)*100), (average ));
                            ((x - average)*100) / average
                        },
                        x if &x <  &average => {
                            // println!("B:: &x <  &average  = {:?} > {:?}", &x, &average);
                            // println!("&x /  &average  = {:?} / {:?}", ((average - x)*100), (average ));
                            ((average - x)*100) / average
                        },
                        _ => { 0 }
                    };
                    // println!("offset_percent = {:?}", &offset_percent);
                    if offset_percent > <PriceAllowableOffset<T>>::get() as u64 {
                        // Set price to abnormal list and pick out check_price
                        <AresAbnormalPrice<T>>::append(key_str.clone(), check_price);
                        // abnormal_price_index_list
                        abnormal_price_index_list.push(index);
                    }
                }

                // println!("All abnormal_price_index_list = {:?}", abnormal_price_index_list);

                let mut remove_count = 0;
                // has abnormal price.
                if abnormal_price_index_list.len() > 0 {
                    // pick out abnormal
                    abnormal_price_index_list.iter().any(|remove_index| {
                        price_list_of_pool.remove((*remove_index - remove_count));
                        remove_count+=1;
                        false
                    });
                    // println!("Update price_list = {:?}", &price_list_of_pool);
                    // reset price pool
                    <AresPrice<T>>::insert(key_str.clone(), price_list_of_pool);
                    return Self::update_avg_price_storage(key_str.clone(), max_len.clone());
                }

                // Update avg price
                <AresAvgPrice<T>>::insert(key_str.clone(), (average, fraction_length));
                // Clear price pool.
                <AresPrice<T>>::remove(key_str.clone());
            }
    }

    // fn get_block_author() -> Option<<<T as pallet::Config>::ValidatorSet as frame_support::traits::ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>
    // {
    //     let digest = <frame_system::Pallet<T>>::digest();
    //     let pre_runtime_digests = digest.logs.iter().filter_map(|d| d.as_pre_runtime());
    //     let author = if let Some(author) = <T as pallet::Config>::FindAuthor::find_author(pre_runtime_digests) {
    //         author
    //     } else {
    //         log::info!("!!!!!!!!!!!!!! find author bad");
    //         Default::default()
    //     };
    //     log::info!("author index == {:?}", author);
    //
    //     let validators = T::VMember
    //     let author_index = author as usize;
    //     if validators.len() <= author_index {
    //         return None;
    //     }
    //
    //     Some(validators[author as usize])
    //
    //     // let encode_data = validators[author as usize];
    //     //
    //     // Some(encode_data.into())
    //     // let author_info = &validators[author as usize];
    //     // log::info!("author info == {:?}", author_info);
    // }


    //
    fn clear_price_storage_data(price_key: Vec<u8>) {
        <AresPrice<T>>::remove(&price_key);
        <AresAvgPrice<T>>::remove(&price_key);
    }

    /// Calculate current average price. // fraction_length: FractionLength
    fn average_price(price_key_str: Vec<u8>, kind: u8 ) -> Option<(u64, FractionLength)> {
        let prices_info = <AresPrice<T>>::get(price_key_str.clone());
        // println!("average_price AAAA = {:?} ", &prices_info);
        let mut fraction_length_of_pool : FractionLength  = 0;
        // Check and get fraction_length.
        prices_info.clone().into_iter().any(|(_,_,_,tmp_fraction,_)| {
            if 0 == fraction_length_of_pool {
                fraction_length_of_pool = tmp_fraction;
            }
            if fraction_length_of_pool != tmp_fraction {
                panic!("Inconsistent of fraction lenght.")
            }
            false
        }) ;

        let prices: Vec<u64> = prices_info.into_iter().map(|(price,_,_,_, _)| price ).collect();
        // println!("average_price BBBB = {:?} ", &prices);
        if prices.is_empty() {
            return None;
        }

        match Self::calculation_average_price(prices, kind) {
            Some(price_value) => {
                return Some((price_value, fraction_length_of_pool));
            },
            _ => {}
        }
        None
    }

    fn calculation_average_price(mut prices: Vec<u64>, kind: u8) -> Option<u64> {
        if 2 == kind {
            // use median
            prices.sort();
            if prices.len() % 2 == 0 {
                // get 2 mid element then calculation average.
                return Some((prices[prices.len() /2 ] + prices[prices.len() /2 -1]) / 2);
            } else {
                // get 1 mid element and return.
                return Some(prices[prices.len() /2 ]);
            }
        }
        if 1 == kind {
            return Some(prices.iter().fold(0_u64, |a, b| a.saturating_add(*b)) / prices.len() as u64)
        }
        None
    }

    fn validate_transaction_parameters_of_ares(
        block_number: &T::BlockNumber,
        _price_list: Vec<(Vec<u8>, u64, FractionLength, JsonNumberValue)>,
    ) -> TransactionValidity {

        // // Now let's check if the transaction has any chance to succeed.
        // let next_unsigned_at = <NextUnsignedAt<T>>::get();
        // if &next_unsigned_at > block_number {
        //     return InvalidTransaction::Stale.into();
        // }

        // Let's make sure to reject transactions from the future.
        let current_block = <system::Pallet<T>>::block_number();
        if &current_block < block_number {
            return InvalidTransaction::Future.into();
        }

        // TODO::This tag prefix need change.
        ValidTransaction::with_tag_prefix("pallet-ocw::validate_transaction_parameters_of_ares")
            .priority(T::UnsignedPriority::get())
            .and_provides(block_number) // next_unsigned_at
            .longevity(5)
            .propagate(true)
            .build()
    }
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    Ok(s.as_bytes().to_vec())
}

#[derive(Deserialize, Encode, Decode, Clone, Default)]
struct LocalPriceRequestStorage {
    // Specify our own deserializing function to convert JSON string to vector of bytes
    #[serde(deserialize_with = "de_string_to_bytes")]
    price_key: Vec<u8>,
    #[serde(deserialize_with = "de_string_to_bytes")]
    request_url: Vec<u8>,
    parse_version: u32,
}

impl fmt::Debug for LocalPriceRequestStorage {
    // `fmt` converts the vector of bytes inside the struct back to string for
    //  more friendly display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ price_key: {}, request_url: {}, parse_version: {}}}",
            str::from_utf8(&self.price_key).map_err(|_| fmt::Error)?,
            str::from_utf8(&self.request_url).map_err(|_| fmt::Error)?,
            &self.parse_version,
        )
    }
}
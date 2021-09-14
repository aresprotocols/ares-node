#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::{
    self as system,
    offchain::{
        AppCrypto, CreateSignedTransaction,
        SignedPayload, SigningTypes,
    },
};

use sp_core::crypto::KeyTypeId;
use sp_runtime::{RuntimeDebug, offchain::{http, Duration}, transaction_validity::{InvalidTransaction, ValidTransaction, TransactionValidity}, RuntimeAppPublic, AccountId32};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
use lite_json::json::JsonValue;

use frame_support::traits::{ Get, ValidatorSet, FindAuthor};

#[cfg(test)]
mod tests;

/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"ares");

#[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug)]
pub enum PriceKey {
    PriceKeyIsNone, // PRICE_KEY_IS_NONE,
    PriceKeyIsBTC, // PRICE_KEY_IS_BTC,
    PriceKeyIsETH, // PRICE_KEY_IS_ETH,
    PriceKeyIsDOT, // PRICE_KEY_IS_DOT,
    PriceKeyIsXRP, // PRICE_KEY_IS_XRP,
}

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

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use super::*;
    use frame_support::sp_runtime::traits::{IdentifyAccount};

    // #[pallet::error]
    // pub enum Error<T> {
    //     ///
    //     UnknownAresPriceVersionNum,
    // }

    /// This pallet's configuration trait
    #[pallet::config]
    pub trait Config: CreateSignedTransaction<Call<Self>> + pallet_authorship::Config + frame_system::Config
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
        type AuthorityAres: Member + Parameter + RuntimeAppPublic + Default + Ord + MaybeSerializeDeserialize;

        /// A type for retrieving the validators supposed to be online in a session.
        type ValidatorSet: ValidatorSet<Self::AccountId>;


        /// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
        #[pallet::constant]
        type UnsignedInterval: Get<Self::BlockNumber>;

        /// A configuration for base priority of unsigned transactions.
        ///
        /// This is exposed so that it can be tuned for particular runtime, when
        /// multiple pallets send unsigned transactions.
        #[pallet::constant]
        type UnsignedPriority: Get<TransactionPriority>;

        // A configuration for PricePayload::price size.
        #[pallet::constant]
        type PriceVecMaxSize: Get<u32>;

        #[pallet::constant]
        type MaxCountOfPerRequest: Get<u8>;

        #[pallet::constant]
        type NeedVerifierCheck: Get<bool>;

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
            if Self::are_block_author_and_sotre_key_the_same() {
                // Try to get ares price.
                match Self::ares_price_worker(block_number) {
                    Ok(v) => log::info!("Ares price at work : {:?}", v),
                    Err(e) => log::warn!("ERROR:: Ares price has a problem : {:?}", e),
                }
            }

            // TODO:: Try simplifying the block_ The acquisition link theory of author can skip pallet_ Authorship, here is a test to see what is returned by babe's findauthor. The work is not completed yet, and other more important work needs to be carried out first.
            // let digest = <frame_system::Pallet<T>>::digest();
            // let pre_runtime_digests = digest.logs.iter().filter_map(|d| d.as_pre_runtime());
            // TODO:: Try to simplify the method ：： log::info!(" $$$$$$$$$$ FindAuthor {:?}", <T as pallet::Config>::FindAuthor::find_author(pre_runtime_digests));
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
            price_payload: PricePayload<T::Public, T::BlockNumber>,
            _signature: T::Signature
        ) -> DispatchResultWithPostInfo {
            // This ensures that the function can only be called via unsigned transaction.
            ensure_none(origin)?;
            // Nodes with the right to increase prices
            let price_list = price_payload.price; // price_list: Vec<(PriceKey, u32)>,

            let mut event_result: Vec<(Vec<u8>, u32)> = Vec::new();
            for (price_key, price) in price_list.clone() {
                // Add the price to the on-chain list, but mark it as coming from an empty address.
                Self::add_price(price_payload.public.clone().into_account(), price.clone(), price_key.clone(), T::PriceVecMaxSize::get());
                event_result.push((Self::get_price_key_str(price_key).as_bytes().to_vec(),price));
            }

            // Self::deposit_event(Event::KittyCreate(who, kitty_id));
            Self::deposit_event(Event::NewPrice(event_result , price_payload.public.clone().into_account()));
            // Self::deposit_event(Event::NewPrice(price_list , price_payload.public.clone().into_account()));

            // now increment the block number at which we expect next unsigned transaction.
            let current_block = <system::Pallet<T>>::block_number();
            <NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
            Ok(().into())
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>
    {
        /// Event generated when new price is accepted to contribute to the average.
        /// \[price, who\]
        // NewPrice(u32, Vec<u8>, T::AccountId),
        NewPrice(Vec<(Vec<u8>, u32)>, T::AccountId),
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
              u64: From<<T as frame_system::Config>::BlockNumber>,
        <T as frame_system::Config>::AccountId: From<<<T as pallet::Config>::ValidatorSet as frame_support::traits::ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>
    {
        type Call = Call<T>;


        fn validate_unsigned(
            _source: TransactionSource,
            call: &Self::Call,
        ) -> TransactionValidity
        {
            if let Call::submit_price_unsigned_with_signed_payload(
                ref payload, ref signature
            ) = call {
                // Get all validators.
                let current_validators = T::ValidatorSet::validators();

                // Check Signer in validator group.
                let mut find_validator = !T::NeedVerifierCheck::get() ; // Self::get_default_find_validator_bool();
                for validator in current_validators {
                    log::info!("=============== Loop {:?} Signer {:?}", validator.clone(), payload.public.clone() );
                    let account : T::AccountId = <T as SigningTypes>::Public::into_account( payload.public.clone());
                    let validator_account : T::AccountId = validator.into();
                    log::info!("=============== account {:?} validator_account {:?}", account.clone(), validator_account.clone() );
                    if account == validator_account {
                        find_validator = true;
                    }
                }

                if !find_validator {
                    log::info!("=============== Validator check failed !!!! ..");
                    return InvalidTransaction::BadProof.into();
                }

                let signature_valid = SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
                if !signature_valid {
                    log::info!("=============== BadProof.into() !!!! ..");
                    return InvalidTransaction::BadProof.into();
                }
                Self::validate_transaction_parameters_of_ares(&payload.block_number, payload.price.to_vec())
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }


    /// A vector of recently submitted prices.
    ///
    /// This is used to calculate average price, should have bounded size.
    // #[pallet::storage]
    // #[pallet::getter(fn prices)]
    // pub(super) type Prices<T: Config> = StorageValue<_, Vec<u32>, ValueQuery>;
    #[pallet::storage]
    #[pallet::getter(fn prices_trace)]
    pub(super) type PricesTrace<T: Config> = StorageValue<_, Vec<(u32, T::AccountId, T::AccountId)>, ValueQuery>;

    /// The lookup table for names.
    #[pallet::storage]
    #[pallet::getter(fn ares_prices)]
    pub(super) type AresPrice<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,
        Vec<u32>,
        ValueQuery
    >;

    #[pallet::storage]
    #[pallet::getter(fn ares_avg_prices)]
    pub(super) type AresAvgPrice<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,
        u32,
        ValueQuery
    >;

    /// Defines the block when next unsigned transaction will be accepted.
    ///
    /// To prevent spam of unsigned (and unpayed!) transactions on the network,
    /// we only allow one transaction every `T::UnsignedInterval` blocks.
    /// This storage entry defines when new transaction is going to be accepted.
    #[pallet::storage]
    #[pallet::getter(fn next_unsigned_at)]
    pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;
}

/// Payload used by this example crate to hold price
/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PricePayload<Public, BlockNumber> {
    block_number: BlockNumber,
    price: Vec<(PriceKey, u32)>,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PricePayload<T::Public, T::BlockNumber> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: Config> Pallet<T>
    where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>,
          u64: From<<T as frame_system::Config>::BlockNumber>
{
    fn are_block_author_and_sotre_key_the_same() -> bool {
        let mut is_same = !T::NeedVerifierCheck::get(); // Self::get_default_author_save_bool();
        let worker_ownerid_list = T::AuthorityAres::all();
        for ownerid in worker_ownerid_list.iter() {
            let mut a = [0u8; 32];
            a[..].copy_from_slice(&ownerid.to_raw_vec());
            // extract AccountId32 from store keys
            let owner_account_id32 = AccountId32::new(a);
            // get Block owner info
            let block_author = <pallet_authorship::Pallet<T>>::author();

            // on debug!
            log::info!("Checking ... owner_account_id32 == block_author.into()");
            let test_into: AccountId32 = block_author.clone().into();
            log::info!("{:?} == {:?}", owner_account_id32.clone(), test_into);
            // debug end.
            if owner_account_id32 == block_author.into() {
                is_same = true;
            }
        }
        is_same
    }

    // Assert whether the block can be submit price.
    fn is_submittable_block_now(block_number: T::BlockNumber) ->bool {
        let next_unsigned_at = <NextUnsignedAt<T>>::get();
        if next_unsigned_at > block_number {
            log::info!("Wait next_unsigned_at > block_number = {:?} > {:?}", next_unsigned_at, block_number);
            return false;
        }
        return true;
    }

    /// Obtain ares price and submit it.
    fn ares_price_worker(block_number: T::BlockNumber) -> Result<(), &'static str> {

        if !Self::is_submittable_block_now(block_number) {
            return Err("It's too early.");
        }

        // let res = Self::fetch_ares_price_and_send_raw_unsigned(block_number); // PriceKey::PRICE_KEY_IS_ETH
        let res = Self::save_fetch_ares_price_and_send_payload_signed(block_number, T::MaxCountOfPerRequest::get()); // PriceKey::PRICE_KEY_IS_ETH

        if let Err(e) = res {
            log::error!("ERROR:: fetch_ares_price_and_send_raw_unsigned on offchain 2: {:?}", e);
        }

        Ok(())
    }

    // get uri key raw of ARES price
    fn get_price_source_list () ->Vec<(PriceKey, &'static str, u32)> {
        let mut price_key_list = Vec::new();
        price_key_list.push((PriceKey::PriceKeyIsBTC, "http://141.164.58.241:5566/api/getPartyPrice/btcusdt", 1u32));
        price_key_list.push((PriceKey::PriceKeyIsETH, "http://141.164.58.241:5566/api/getPartyPrice/ethusdt", 1u32));
        price_key_list.push((PriceKey::PriceKeyIsDOT, "http://141.164.58.241:5566/api/getPartyPrice/dotusdt", 1u32));
        price_key_list.push((PriceKey::PriceKeyIsXRP, "http://141.164.58.241:5566/api/getPartyPrice/xrpusdt", 1u32));
        price_key_list
    }

    // get string iden of price key
    fn get_price_key_str (price_key: PriceKey) -> &'static str {
        match price_key {
            PriceKey::PriceKeyIsBTC => {"btc_price"}
            PriceKey::PriceKeyIsETH => {"eth_price"}
            PriceKey::PriceKeyIsDOT => {"dot_price"}
            PriceKey::PriceKeyIsXRP => {"xrp_price"}
            PriceKey::PriceKeyIsNone => {"__none_price"}
        }
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
    fn get_delimited_price_source_list(source_list: Vec<(PriceKey, &str, u32)>, round_number: u64, max_request_count: u8) -> Vec<(PriceKey, &str, u32)> {
        let vec_count = source_list.len() as u8 ;

        let remainder_split_num = Self::get_number_of_cycles(vec_count, max_request_count);
        if remainder_split_num <= 0 {
            return Vec::new();
        }

        let remainder : u64 =  (round_number % remainder_split_num as u64).into();
        let begin_index = remainder * max_request_count as u64;
        let mut end_index = begin_index + max_request_count as u64;
        if end_index > source_list.len() as u64 {
            end_index = source_list.len() as u64;
        }

        source_list[begin_index as usize .. end_index as usize].to_vec()
    }

    fn save_fetch_ares_price_and_send_payload_signed(block_number: T::BlockNumber, max_request_count: u8) -> Result<(), &'static str> {

        let price_source_list = Self::get_delimited_price_source_list(Self::get_price_source_list(), block_number.into(), max_request_count);
        let mut price_list = Vec::new();
        for (price_key, request_url, version_num) in price_source_list {
            if let Ok(price) = Self::fetch_price_body_with_http(price_key.clone(), request_url, version_num) {
                // add price to price_list
                price_list.push((price_key, price));
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

    /// Fetch current price and return the result in cents.
    fn fetch_price_body_with_http(_price_key: PriceKey, request_url: &str, version_num: u32) -> Result<u32, http::Error> {

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
                let price = match Self::parse_price_of_ares(body_str) {
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

    fn parse_price_of_ares(price_str: &str) -> Option<u32> {
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

        let exp = price.fraction_length.checked_sub(2).unwrap_or(0);
        Some(price.integer as u32 * 100 + (price.fraction / 10_u64.pow(exp)) as u32)
    }



    //
    fn add_price(who: T::AccountId, price: u32, price_key: PriceKey, max_len:u32 ) {
        let key_str = Self::get_price_key_str(price_key);
        let price_key_str = key_str.as_bytes().to_vec();

        // let price_key = "btc_price".as_bytes().to_vec();
        // 1. Check key exists
        if <AresPrice<T>>::contains_key(price_key_str.clone()) {
            // get and reset .
            let mut old_price = <AresPrice<T>>::get(price_key_str.clone());
            let MAX_LEN: usize = max_len.clone() as usize;
            if old_price.len() < MAX_LEN {
                old_price.push(price.clone());
            } else {
                old_price[price as usize % MAX_LEN] = price.clone();
            }
            <AresPrice<T>>::insert(price_key_str.clone(), old_price);
        } else {
            // push a new value.
            let mut new_price: Vec<u32> = Vec::new();
            new_price.push(price.clone());
            <AresPrice<T>>::insert(price_key_str.clone(), new_price);
        }

        // Get current block number for test.
        let current_block = <system::Pallet<T>>::block_number();
        log::info!("======= DEBUG:: current blocknum : {:?}, {:?}", current_block, key_str);

        <PricesTrace<T>>::mutate(|prices_trace| {
            let author = <pallet_authorship::Pallet<T>>::author();
            log::info!("LIN:DEBUG price_trace {:?}, {:?}, {:?},{:?},{:?}", key_str, current_block, price.clone(), author.clone(), who.clone());
            let MAX_LEN: usize = max_len.clone() as usize;
            let price_trace_len = prices_trace.len();
            if price_trace_len < MAX_LEN {
                prices_trace.push((price.clone(), author.clone(), who.clone()));
            } else {
                prices_trace[price_trace_len % MAX_LEN] = (price.clone(), author.clone(), who.clone());
            }
        });

        let average = Self::average_price(price_key_str.clone())
            .expect("The average is not empty, because it was just mutated; qed");
        log::info!("Calculate current average price average price is: {} , {:?}", average, key_str);
        // Update avg price
        <AresAvgPrice<T>>::insert(price_key_str.clone(), average);

        // here we are raising the NewPrice event
        // Self::deposit_event(Event::NewPrice(price, key_str.as_bytes().to_vec() , who));
    }

    /// Calculate current average price.
    fn average_price(price_key_str: Vec<u8>) -> Option<u32> {
        let prices = <AresPrice<T>>::get(price_key_str.clone());
        if prices.is_empty() {
            None
        } else {
            Some(prices.iter().fold(0_u32, |a, b| a.saturating_add(*b)) / prices.len() as u32)
        }
    }

    fn validate_transaction_parameters_of_ares(
        block_number: &T::BlockNumber,
        _price_list: Vec<(PriceKey, u32)>,
    ) -> TransactionValidity {
        // Now let's check if the transaction has any chance to succeed.
        let next_unsigned_at = <NextUnsignedAt<T>>::get();
        if &next_unsigned_at > block_number {
            return InvalidTransaction::Stale.into();
        }
        // Let's make sure to reject transactions from the future.
        let current_block = <system::Pallet<T>>::block_number();
        if &current_block < block_number {
            return InvalidTransaction::Future.into();
        }
        // TODO::This tag prefix need change.
        ValidTransaction::with_tag_prefix("pallet-ocw::validate_transaction_parameters_of_ares")
            .priority(T::UnsignedPriority::get())
            .and_provides(next_unsigned_at)
            .longevity(5)
            .propagate(true)
            .build()
    }
}

#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::{
    self as system,
    offchain::{
        AppCrypto, CreateSignedTransaction,
        SignedPayload, SigningTypes, SubmitTransaction,
    },
};
use frame_support::traits::Get;
use sp_core::crypto::KeyTypeId;
use sp_runtime::{RuntimeDebug, offchain::{http, Duration}, transaction_validity::{InvalidTransaction, ValidTransaction, TransactionValidity}, RuntimeAppPublic, AccountId32};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
use lite_json::json::JsonValue;

#[cfg(test)]
mod tests;

/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"ares");

#[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug)]
pub enum PriceKey {
    PRICE_KEY_IS_NONE,
    PRICE_KEY_IS_BTC,
    PRICE_KEY_IS_ETH,
}
// pub const PRICE_KEY_IS_NONE: Vec<u8> = "__none_price".as_bytes().to_vec();
// pub const PRICE_KEY_IS_BTC: Vec<u8> = "btc_price".as_bytes().to_vec();

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
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

    // struct for test.
    pub struct TestAuthId;

    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for TestAuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    // struct fro production
    pub struct OcwAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for OcwAuthId {
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

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use super::*;
    use frame_system::Account;

    /// This pallet's configuration trait
    #[pallet::config]
    pub trait Config: CreateSignedTransaction<Call<Self>> + pallet_authorship::Config + frame_system::Config
        where sp_runtime::AccountId32: From<<Self as frame_system::Config>::AccountId>
    {
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// The overarching dispatch call type.
        type Call: From<Call<Self>>;

        /// ocw store key pair.
        type AuthorityAres: Member + Parameter + RuntimeAppPublic + Default + Ord + MaybeSerializeDeserialize;

        /// A grace period after we send transaction.
        ///
        /// To avoid sending too many transactions, we only attempt to send one
        /// every `GRACE_PERIOD` blocks. We use Local Storage to coordinate
        /// sending between distinct runs of this offchain worker.
        #[pallet::constant]
        type GracePeriod: Get<Self::BlockNumber>;

        /// Number of blocks of cooldown after unsigned transaction is included.
        ///
        /// This ensures that we only accept unsigned transactions once, every `UnsignedInterval` blocks.
        #[pallet::constant]
        type UnsignedInterval: Get<Self::BlockNumber>;

        /// A configuration for base priority of unsigned transactions.
        ///
        /// This is exposed so that it can be tuned for particular runtime, when
        /// multiple pallets send unsigned transactions.
        #[pallet::constant]
        type UnsignedPriority: Get<TransactionPriority>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    // impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>
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
        }
    }

    /// A public part of the pallet.
    #[pallet::call]
    impl<T: Config> Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>
    {
        /// Submit new price to the list.
        ///
        /// This method is a public function of the module and can be called from within
        /// a transaction. It appends given `price` to current list of prices.
        /// In our example the `offchain worker` will create, sign & submit a transaction that
        /// calls this function passing the price.
        ///
        /// The transaction needs to be signed (see `ensure_signed`) check, so that the caller
        /// pays a fee to execute it.
        /// This makes sure that it's not easy (or rather cheap) to attack the chain by submitting
        /// excesive transactions, but note that it doesn't ensure the price oracle is actually
        /// working and receives (and provides) meaningful data.
        /// This example is not focused on correctness of the oracle itself, but rather its
        /// purpose is to showcase offchain worker capabilities.
        // #[pallet::weight(0)]
        // pub fn submit_price(origin: OriginFor<T>, price: u32, price_key: PriceKey) -> DispatchResultWithPostInfo {
        //     // Retrieve sender of the transaction.
        //     let who = ensure_signed(origin)?;
        //     // Add the price to the on-chain list.
        //     Self::add_price(who, price, price_key);
        //     Ok(().into())
        // }

        /// Submit new price to the list via unsigned transaction.
        ///
        /// Works exactly like the `submit_price` function, but since we allow sending the
        /// transaction without a signature, and hence without paying any fees,
        /// we need a way to make sure that only some transactions are accepted.
        /// This function can be called only once every `T::UnsignedInterval` blocks.
        /// Transactions that call that function are de-duplicated on the pool level
        /// via `validate_unsigned` implementation and also are rendered invalid if
        /// the function has already been called in current "session".
        ///
        /// It's important to specify `weight` for unsigned calls as well, because even though
        /// they don't charge fees, we still don't want a single block to contain unlimited
        /// number of such transactions.
        ///
        /// This example is not focused on correctness of the oracle itself, but rather its
        /// purpose is to showcase offchain worker capabilities.
        #[pallet::weight(0)]
        pub fn submit_price_unsigned(
            origin: OriginFor<T>,
            _block_number: T::BlockNumber,
            price_list: Vec<(PriceKey, u32)>,
        ) -> DispatchResultWithPostInfo
        {
            ensure_none(origin)?;

            // Nodes with the right to increase prices
            for (price_key, price) in price_list {
                // Add the price to the on-chain list, but mark it as coming from an empty address.
                Self::add_price(Default::default(), price, price_key);
            }

            // now increment the block number at which we expect next unsigned transaction.
            let current_block = <system::Pallet<T>>::block_number();
            // update NextUnsignedAt
            <NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());

            Ok(().into())
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>
    {
        /// Event generated when new price is accepted to contribute to the average.
        /// \[price, who\]
        NewPrice(u32, T::AccountId),
    }

    // #[pallet::error]
    // pub enum Error<T>
    // {
    //     StoreKeyErr,
    // }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T>
        where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>
    {
        type Call = Call<T>;

        /// Validate unsigned call to this module.
        ///
        /// By default unsigned transactions are disallowed, but implementing the validator
        /// here we make sure that some particular calls (the ones produced by offchain worker)
        /// are being whitelisted and marked as valid.
        fn validate_unsigned(
            _source: TransactionSource,
            call: &Self::Call,
        ) -> TransactionValidity {
            if let Call::submit_price_unsigned(block_number, ref price_list) = call {
                Self::validate_transaction_parameters_of_ares(block_number, price_list.to_vec())
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
    price: u32,
    public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PricePayload<T::Public, T::BlockNumber> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: Config> Pallet<T>
    where sp_runtime::AccountId32: From<<T as frame_system::Config>::AccountId>
{
    fn are_block_author_and_sotre_key_the_same() -> bool {
        let mut is_same = false;
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

    /// Obtain ares price and submit it.
    fn ares_price_worker(block_number: T::BlockNumber) -> Result<(), &'static str> {
        let next_unsigned_at = <NextUnsignedAt<T>>::get();
        log::info!("next_unsigned_at > block_number = {:?} > {:?}", next_unsigned_at, block_number);
        if next_unsigned_at > block_number {
            return Err("Too early to send unsigned transaction of ares, on fetch_ares_price_and_send_raw_unsigned");
        }

        let res = Self::fetch_ares_price_and_send_raw_unsigned(block_number); // PriceKey::PRICE_KEY_IS_ETH
        // TODO:: Add signed transaction method with save used
        if let Err(e) = res {
            log::error!("ERROR:: fetch_ares_price_and_send_raw_unsigned on offchain 2: {:?}", e);
        }

        Ok(())
    }

    // Submit price information without signature
    fn fetch_ares_price_and_send_raw_unsigned(block_number: T::BlockNumber) -> Result<(), &'static str> {
        let mut price_key_list = Vec::new();
        price_key_list.push(PriceKey::PRICE_KEY_IS_BTC);
        price_key_list.push(PriceKey::PRICE_KEY_IS_ETH);

        let mut price_list = Vec::new();
        for price_key in price_key_list {
            if let Ok(price) = Self::fetch_price_of_ares(price_key.clone()) {
                // add price to price_list
                price_list.push((price_key, price));
            }
        }

        if price_list.len() > 0 {
            // Received price is wrapped into a call to `submit_price_unsigned` public function of this pallet.
            let call = Call::submit_price_unsigned(block_number, price_list);

            // Now let's create a transaction out of this call and submit it to the pool.
            SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
                .map_err(|()| "ERROR:: Unable to submit unsigned transaction.")?;
        }

        Ok(())
    }

    /// Fetch current price and return the result in cents.
    fn fetch_price_of_ares(price_key: PriceKey) -> Result<u32, http::Error> {

        // Choose the corresponding address.
        let request_url = match price_key {
            PriceKey::PRICE_KEY_IS_BTC => {
                "http://141.164.58.241:5566/api/getPartyPrice/btcusdt"
            }
            PriceKey::PRICE_KEY_IS_ETH => {
                "http://141.164.58.241:5566/api/getPartyPrice/ethusdt"
            }
            _ => {
                ""
            }
        };

        if "" == request_url {
            log::warn!("ERROR:: Cannot match area pricer url. ");
            return Err(http::Error::Unknown);
        }

        log::info!("Go to fetch_price_of_ares ");
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
        let price = match Self::parse_price_of_ares(body_str) {
            Some(price) => Ok(price),
            None => {
                log::warn!("Unable to extract price from the response: {:?}", body_str);
                Err(http::Error::Unknown)
            }
        }?;
        log::info!("Get the price {:?} provided by Ares", price);
        Ok(price)
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
    fn add_price(who: T::AccountId, price: u32, price_key: PriceKey) {
        let key_str = match price_key {
            PriceKey::PRICE_KEY_IS_BTC => {
                "btc_price"
            }
            PriceKey::PRICE_KEY_IS_ETH => {
                "eth_price"
            }
            PriceKey::PRICE_KEY_IS_NONE => {
                "__none_price"
            }
        };

        let price_key_str = key_str.as_bytes().to_vec();

        // let price_key = "btc_price".as_bytes().to_vec();
        // 1. Check key exists
        if <AresPrice<T>>::contains_key(price_key_str.clone()) {
            // get and reset .
            let mut old_price = <AresPrice<T>>::get(price_key_str.clone());
            const MAX_LEN: usize = 50;
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

        // <AresPrice<T>>::get

        // Get current block number for test.
        let current_block = <system::Pallet<T>>::block_number();
        log::info!("======= DEBUG:: current blocknum : {:?}, {:?}", current_block, key_str);

        // let mut session_account = Self::get_session_account();
        <PricesTrace<T>>::mutate(|prices_trace| {
            let author = <pallet_authorship::Pallet<T>>::author();
            log::info!("LIN:DEBUG price_trace {:?}, {:?}, {:?},{:?},{:?}", key_str, current_block, price.clone(), author.clone(), who.clone());

            // prices_trace.push((price.clone(), author.clone(), who.clone()));

            const MAX_LEN: usize = 50;
            let price_trace_len = prices_trace.len();
            if price_trace_len < MAX_LEN {
                prices_trace.push((price.clone(), author.clone(), who.clone()));
            } else {
                prices_trace[price_trace_len % MAX_LEN] = (price.clone(), author.clone(), who.clone());
            }
        });

        let average = Self::average_price(price_key_str.clone())
            .expect("The average is not empty, because it was just mutated; qed");
        log::info!("LIN:DEBUG Current average price is: {} , {:?}", average, key_str);

        // here we are raising the NewPrice event
        Self::deposit_event(Event::NewPrice(price, who));
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
        price_list: Vec<(PriceKey, u32)>,
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

        // The key is the same as the author of the current block.
        // if false == Self::are_block_author_and_sotre_key_the_same() {
        //     return InvalidTransaction::BadProof.into();
        // }

        // TODO::This tag prefix need change.
        ValidTransaction::with_tag_prefix("pallet-ocw::submit_price_unsigned")
            // We set base priority to 2**20 and hope it's included before any other
            // transactions in the pool. Next we tweak the priority depending on how much
            // it differs from the current average. (the more it differs the more priority it
            // has).
            // .priority(T::UnsignedPriority::get().saturating_add(avg_price as _))
            .priority(T::UnsignedPriority::get())

            // This transaction does not require anything else to go before into the pool.
            // In theory we could require `previous_unsigned_at` transaction to go first,
            // but it's not necessary in our case.
            //.and_requires()
            // We set the `provides` tag to be the same as `next_unsigned_at`. This makes
            // sure only one transaction produced after `next_unsigned_at` will ever
            // get to the transaction pool and will end up in the block.
            // We can still have multiple transactions compete for the same "spot",
            // and the one with higher priority will replace other one in the pool.
            .and_provides(next_unsigned_at)
            // The transaction is only valid for next 5 blocks. After that it's
            // going to be revalidated by the pool.
            .longevity(5)
            // It's fine to propagate that transaction to other peers, which means it can be
            // created even by nodes that don't produce blocks.
            // Note that sometimes it's better to keep it for yourself (if you are the block
            // producer), since for instance in some schemes others may copy your solution and
            // claim a reward.
            .propagate(true)
            .build()
    }
}

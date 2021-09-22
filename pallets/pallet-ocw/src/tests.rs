// This file is part of Substrate.

// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::*;
use crate as ares_ocw_worker;
use codec::Decode;
use frame_support::{assert_ok, parameter_types, ord_parameter_types, ConsensusEngineId, traits::GenesisBuild};
use std::sync::Arc;
use pallet_session::historical as pallet_session_historical;
use sp_core::{
    H256,
    offchain::{OffchainWorkerExt, TransactionPoolExt, OffchainDbExt, testing::{self, TestOffchainExt, TestTransactionPoolExt}},
    sr25519::Signature,
};

use sp_keystore::{
    {KeystoreExt, SyncCryptoStore},
    testing::KeyStore,
};
use frame_system::{EventRecord, Phase};
use std::cell::RefCell;

use sp_runtime::{
    Perbill,
    testing::{Header, TestXt, UintAuthorityId},
    traits::{
        BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
        IdentifyAccount, Verify,
    },
};

use sp_core::sr25519::Public as Public;
// use pallet_session::historical as pallet_session_historical;
use frame_support::traits::{FindAuthor, VerifySeal};
use pallet_authorship::SealVerify;
use sp_staking::SessionIndex;
use sp_runtime::traits::AppVerify;

use frame_system::{EnsureSignedBy, EnsureRoot};
use std::convert::TryInto;
use sp_core::hexdisplay::HexDisplay;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// For testing the module, we construct a mock runtime.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
        // Staking: pallet_staking::{Pallet, Call, Config<T>, Storage, Event<T>},
		Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
        Historical: pallet_session_historical::{Pallet},
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		AresOcw: ares_ocw_worker::{Pallet, Call, Storage, Event<T>, ValidateUnsigned},
		Authorship: pallet_authorship::{Pallet, Call, Storage, Inherent},
	}
);


#[cfg(feature = "historical")]
impl crate::historical::Config for Test {
    type FullIdentification = u64;
    type FullIdentificationOf = sp_runtime::traits::ConvertInto;
}

const TEST_ID: ConsensusEngineId = [1, 2, 3, 4];
pub struct AuthorGiven;
impl FindAuthor<Public> for AuthorGiven {
    fn find_author<'a, I>(digests: I) -> Option<Public>
        where I: 'a + IntoIterator<Item=(ConsensusEngineId, &'a [u8])>
    {
        for (id, data) in digests {
            if id == TEST_ID {
                return Public::decode(&mut &data[..]).ok();
            }
        }
        None
    }
}

pub struct VerifyBlock;
impl VerifySeal<Header, Public> for VerifyBlock {
    fn verify_seal(header: &Header) -> Result<Option<Public>, &'static str> {
        let pre_runtime_digests = header.digest.logs.iter().filter_map(|d| d.as_pre_runtime());
        let seals = header.digest.logs.iter().filter_map(|d| d.as_seal());

        let author = AuthorGiven::find_author(pre_runtime_digests).ok_or_else(|| "no author")?;

        for (id, seal) in seals {
            if id == TEST_ID {
                match Public::decode(&mut &seal[..]) {
                    Err(_) => return Err("wrong seal"),
                    Ok(a) => {
                        if a != author {
                            return Err("wrong author in seal");
                        }
                        break
                    }
                }
            }
        }
        Ok(Some(author))
    }
}

parameter_types! {
	pub const UncleGenerations: u32 = 5;
}

impl pallet_authorship::Config for Test {
    type FindAuthor = AuthorGiven;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = SealVerify<VerifyBlock>;
    type EventHandler = ();
}

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub BlockWeights: frame_system::limits::BlockWeights =
		frame_system::limits::BlockWeights::simple_max(1024);
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::AllowAll;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
}

type Extrinsic = TestXt<Call, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Test {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test where
    Call: From<LocalCall>,
{
    type OverarchingCall = Call;
    type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test where
    Call: From<LocalCall>,
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: Call,
        _public: <Signature as Verify>::Signer,
        _account: AccountId,
        nonce: u64,
    ) -> Option<(Call, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
        Some((call, (nonce, ())))
    }
}

parameter_types! {
	// pub const GracePeriod: u64 = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
    pub const PriceVecMaxSize: u32 = 3;
    pub const MaxCountOfPerRequest: u8 = 3;
    pub const NeedVerifierCheck: bool = false;
    pub const UseOnChainPriceRequest: bool = true;
    pub const FractionLengthNum: u32 = 2;
    pub const CalculationKind: u8 = 2;
}

ord_parameter_types! {
	pub const One: u64 = 1;
	pub const Two: u64 = 2;
	pub const Three: u64 = 3;
	pub const Four: u64 = 4;
	pub const Five: u64 = 5;
	pub const Six: u64 = 6;
}

impl Config for Test {
    type Event = Event;
    type AuthorityId = crypto::OcwAuthId;
    type AuthorityAres = sr25519::AuthorityId;
    type Call = Call;
    type ValidatorSet = Historical;
    type RequestOrigin = frame_system::EnsureRoot<AccountId>;
    type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
    type PriceVecMaxSize = PriceVecMaxSize;
    type MaxCountOfPerRequest = MaxCountOfPerRequest;
    type NeedVerifierCheck = NeedVerifierCheck;
    type UseOnChainPriceRequest = UseOnChainPriceRequest;
    type FractionLengthNum = FractionLengthNum;
    type CalculationKind = CalculationKind;
}

impl pallet_session::historical::Config for Test {
    type FullIdentification = AccountId;
    type FullIdentificationOf = TestHistoricalConvertInto<Self>;
}

thread_local! {
	pub static VALIDATORS: RefCell<Option<Vec<AccountId>>> = RefCell::new(Some(vec![
		AccountId::from_raw([1;32]),
		AccountId::from_raw([2;32]),
		AccountId::from_raw([3;32]),
	]));
}

pub struct TestSessionManager;
impl pallet_session::SessionManager<AccountId> for TestSessionManager {
    fn new_session(_new_index: SessionIndex) -> Option<Vec<AccountId>> {
        VALIDATORS.with(|l| l.borrow_mut().take())
    }
    fn end_session(_: SessionIndex) {}
    fn start_session(_: SessionIndex) {}
}

impl pallet_session::historical::SessionManager<AccountId, AccountId> for TestSessionManager {
    fn new_session(_new_index: SessionIndex) -> Option<Vec<(AccountId, AccountId)>> {
        VALIDATORS.with(|l| l
            .borrow_mut()
            .take()
            .map(|validators| {
                validators.iter().map(|v| (*v, *v)).collect()
            })
        )
    }
    fn end_session(_: SessionIndex) {}
    fn start_session(_: SessionIndex) {}
}


pub struct TestHistoricalConvertInto<T:pallet_session::historical::Config>(sp_std::marker::PhantomData<T>);
// type FullIdentificationOf: Convert<Self::ValidatorId, Option<Self::FullIdentification>>;
impl <T: pallet_session::historical::Config> sp_runtime::traits::Convert<T::ValidatorId, Option<T::FullIdentification>> for TestHistoricalConvertInto<T>
    where <T as pallet_session::historical::Config>::FullIdentification: From<<T as pallet_session::Config>::ValidatorId>
{
    fn convert(a: T::ValidatorId) -> Option<T::FullIdentification> {
        Some(a.into())
    }
}

parameter_types! {
	pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(33);
}
parameter_types! {
	pub const Period: u64 = 1;
	pub const Offset: u64 = 0;
}
impl pallet_session::Config for Test {
    type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
    type SessionManager = pallet_session::historical::NoteHistoricalRoot<Test, TestSessionManager>;
    type SessionHandler = TestSessionHandler;
    type ValidatorId = AccountId;
    type ValidatorIdOf = TestSessionConvertInto<Self>;
    type Keys = UintAuthorityId;
    type Event = Event;
    type DisabledValidatorsThreshold =();// pallet_session::PeriodicSessions<(), ()>;
    type NextSessionRotation = (); //pallet_session::PeriodicSessions<(), ()>;
    type WeightInfo = ();
}

pub struct TestSessionConvertInto<T>(sp_std::marker::PhantomData<T>);
impl <T: pallet_session::Config> sp_runtime::traits::Convert<AccountId, Option<T::ValidatorId>> for TestSessionConvertInto<T>
    where <T as pallet_session::Config>::ValidatorId: From<sp_application_crypto::sr25519::Public>
{
    fn convert(a: AccountId) -> Option<T::ValidatorId> {
        Some(a.into())
    }
}

pub struct TestSessionHandler;
impl pallet_session::SessionHandler<AccountId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [sp_runtime::KeyTypeId] = &[];

    fn on_genesis_session<Ks: sp_runtime::traits::OpaqueKeys>(_validators: &[(AccountId, Ks)]) {}

    fn on_new_session<Ks: sp_runtime::traits::OpaqueKeys>(
        _: bool,
        _: &[(AccountId, Ks)],
        _: &[(AccountId, Ks)],
    ) {}

    fn on_disabled(_: usize) {}
}

// TODO:: Ares to do.

#[test]
fn test_calculation_average_price() {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.execute_with(|| {
        assert_eq!( Some(6) , AresOcw::calculation_average_price(vec![6,2,1,18,3], CALCULATION_KIND_AVERAGE));
        assert_eq!( Some(3) , AresOcw::calculation_average_price(vec![6,2,1,18,3], CALCULATION_KIND_MEDIAN));
        assert_eq!( Some(17) , AresOcw::calculation_average_price(vec![3,45,18,3], CALCULATION_KIND_AVERAGE));
        assert_eq!( Some(10) , AresOcw::calculation_average_price(vec![3,45,18,3], CALCULATION_KIND_MEDIAN));
        assert_eq!( Some(5) , AresOcw::calculation_average_price(vec![6,5,5], CALCULATION_KIND_AVERAGE));
        assert_eq!( Some(5) , AresOcw::calculation_average_price(vec![6,5,5], CALCULATION_KIND_MEDIAN));
        assert_eq!( Some(70) , AresOcw::calculation_average_price(vec![70], CALCULATION_KIND_AVERAGE));
        assert_eq!( Some(70) , AresOcw::calculation_average_price(vec![70], CALCULATION_KIND_MEDIAN));

    });
}

#[test]
fn test_connect_request_url(){
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {
        assert_eq!(AresOcw::get_local_storage_request_domain(), "http://141.164.58.241:5566");
        assert_eq!(AresOcw::make_local_storage_request_uri_by_str("/get/price1"), "http://141.164.58.241:5566/get/price1".as_bytes().to_vec());
        assert_eq!(AresOcw::make_local_storage_request_uri_by_vec_u8("/get/price2".as_bytes().to_vec()), "http://141.164.58.241:5566/get/price2".as_bytes().to_vec());
    });
}

#[test]
fn addprice_of_ares () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {
        System::set_block_number(1);

        // when
        let price_key = "btc_price".as_bytes().to_vec();// PriceKey::PriceKeyIsBTC ;
        AresOcw::add_price(Default::default(), 8888, price_key.clone(), 4, 2);
        AresOcw::add_price(Default::default(), 9999, price_key.clone(), 4, 2);

        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        // (price_val, accountid, block_num, fraction_num)
        assert_eq!(vec![(8888,Default::default(), 1, 4), (9999,Default::default(), 1, 4)], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((8888 + 9999) / 2, 4));

        // let evt = System::events().into_iter().map(|evt| evt.event).collect::<Vec<_>>();
        // println!("{:?}", evt);
        // println!("{:?}", Event::AresOcw(crate::Event::NewPrice(9999, Default::default())));
        // System::assert_last_event(Event::AresOcw(crate::Event::NewPrice(9999, Default::default())));
        // System::assert_has_event(Event::AresOcw(crate::Event::NewPrice(9999, Default::default())));
        // System::assert_last_event(Event::Balances(crate::Event::Reserved(1, 10)));

        // Add a new value beyond the array boundary.
        AresOcw::add_price(Default::default(), 3333, price_key.clone(), 4, 2);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        // (price_val, accountid, block_num, fraction_num)
        assert_eq!(vec![(8888, Default::default(), 1, 4), (3333, Default::default(), 1, 4)], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((8888 + 3333) / 2, 4));

        // when
        let price_key = "eth_price".as_bytes().to_vec() ;// PriceKey::PriceKeyIsETH ;
        AresOcw::add_price(Default::default(), 7777, price_key.clone(), 4, 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        // (price_val, accountid, block_num, fraction_num)
        assert_eq!(vec![(7777, Default::default(), 1, 4)], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((7777) / 1, 4));

        AresOcw::add_price(Default::default(), 6666, price_key.clone(), 4, 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(7777, Default::default(), 1, 4), (6666, Default::default(), 1, 4)], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((7777 + 6666) / 2, 4));

        // Add a new value beyond the array boundary.
        AresOcw::add_price(Default::default(), 1111, price_key.clone(), 4, 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(7777, Default::default(), 1, 4), (1111, Default::default(), 1, 4)], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((7777 + 1111) / 2, 4));

    });
}

#[test]
fn test_request_price_update_then_the_price_list_will_be_update_if_the_fractioin_length_changed () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {
        System::set_block_number(2);

        // when
        let price_key = "btc_price".as_bytes().to_vec();// PriceKey::PriceKeyIsBTC ;
        AresOcw::add_price(Default::default(), 8888, price_key.clone(), 4, 100);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 2, 4)], btc_price_list);

        AresOcw::add_price(Default::default(), 9999, price_key.clone(), 4, 100);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 2, 4), (9999,Default::default(), 2, 4)], btc_price_list);
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((8888 + 9999) / 2, 4));

        // then fraction changed, old price list will be empty.
        AresOcw::add_price(Default::default(), 6666, price_key.clone(), 3, 100);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(6666,Default::default(), 2, 3)], btc_price_list);
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (6666, 3));

    });
}

#[test]
fn parse_price_ares_works() {

    let test_data = vec![
        (get_are_json_of_btc(), Some(50261)),
        (get_are_json_of_eth(), Some(3107)),
        (get_are_json_of_dot(), Some(35)),
        (get_are_json_of_xrp(), Some(1)),
    ];

    for (json, expected) in test_data {
        let second = AresOcw::parse_price_of_ares(json, 0);
        assert_eq!(expected, second);
    }

    let test_data = vec![
        (get_are_json_of_btc(), Some(5026137)),
        (get_are_json_of_eth(), Some(310771)),
        (get_are_json_of_dot(), Some(3599)),
        (get_are_json_of_xrp(), Some(109)),
    ];

    for (json, expected) in test_data {
        let second = AresOcw::parse_price_of_ares(json, 2);
        assert_eq!(expected, second);
    }

    let test_data = vec![
        (get_are_json_of_btc(), Some(50261372)),
        (get_are_json_of_eth(), Some(3107710)),
        (get_are_json_of_dot(), Some(35992)),
        (get_are_json_of_xrp(), Some(1092)),
    ];

    for (json, expected) in test_data {
        let second = AresOcw::parse_price_of_ares(json, 3);
        assert_eq!(expected, second);
    }

    let test_data = vec![
        (get_are_json_of_btc(), Some(50261372000)),
        (get_are_json_of_eth(), Some(3107710000)),
        (get_are_json_of_dot(), Some(35992100)),
        (get_are_json_of_xrp(), Some(1092720)),
    ];

    for (json, expected) in test_data {
        let second = AresOcw::parse_price_of_ares(json, 6);
        assert_eq!(expected, second);
    }

    // let test_data = vec![
    //     (get_are_json_of_btc(), Some(50261372000_000000)),
    //     (get_are_json_of_eth(), Some(3107710000_000000)),
    //     (get_are_json_of_dot(), Some(35992100_000000)),
    //     (get_are_json_of_xrp(), Some(1092720_000000)),
    // ];
    //
    // for (json, expected) in test_data {
    //     let second = AresOcw::parse_price_of_ares(json, 12);
    //     assert_eq!(expected, second);
    // }
    //
    // let test_data = vec![
    //     (get_are_json_of_btc(), Some(50261372000_000000_000000)),
    //     (get_are_json_of_eth(), Some(3107710000_000000_000000)),
    //     (get_are_json_of_dot(), Some(35992100_000000_000000)),
    //     (get_are_json_of_xrp(), Some(1092720_000000_000000)),
    // ];
    //
    // for (json, expected) in test_data {
    //     let second = AresOcw::parse_price_of_ares(json, 18);
    //     assert_eq!(expected, second);
    // }
}

#[test]
fn should_make_http_call_and_parse_ares_result() {

    // let mut t = sp_io::TestExternalities::default();
    let mut t = new_test_ext();

    let (offchain, state) = testing::TestOffchainExt::new();
    t.register_extension(OffchainWorkerExt::new(offchain));

    let json_response = get_are_json_of_btc().as_bytes().to_vec();

    state.write().expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/btcusdt".into(),
        response: Some(json_response),
        sent: true,
        ..Default::default()
    });

    t.execute_with(|| {
        let price = AresOcw::fetch_price_body_with_http(Vec::new(), "http://141.164.58.241:5566/api/getPartyPrice/btcusdt", 1u32, 2).unwrap();
        assert_eq!(price, 5026137);
    });
}

#[test]
fn save_fetch_ares_price_and_send_payload_signed() {

    let mut t = new_test_ext();

    const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    SyncCryptoStore::sr25519_generate_new(
        &keystore,
        crate::crypto::Public::ID,
        Some(&format!("{}/hunter1", PHRASE))
    ).unwrap();

    let public_key = SyncCryptoStore::sr25519_public_keys(&keystore, crate::crypto::Public::ID)
        .get(0)
        .unwrap()
        .clone();

    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));


    let padding_request = testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/xrpusdt".into(),
        response: Some(get_are_json_of_xrp().as_bytes().to_vec()),
        sent: true,
        ..Default::default()
    };

    offchain_state.write().expect_request(padding_request);

    let price_payload_b1 = PricePayload {
        block_number: 1, // type is BlockNumber
        price: vec![
            // (PriceKey::PriceKeyIsBTC, 5026137u32),
            // (PriceKey::PriceKeyIsETH, 310771),
            // (PriceKey::PriceKeyIsDOT, 3599),
            // price_key, price_val, fraction_num
            ("xrp_price".as_bytes().to_vec(), 10927, 4),
        ],
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    // println!("RUN 1 -------------");
    assert_eq!(3, <Test as crate::Config>::MaxCountOfPerRequest::get(), "Current use MaxCount is 3");

    // let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
    t.execute_with(|| {
        // when execute blocknumber = 1
        AresOcw::save_fetch_ares_price_and_send_payload_signed(1, <Test as crate::Config>::MaxCountOfPerRequest::get()).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        if let Call::AresOcw(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
            assert_eq!(body.clone(), price_payload_b1);
            let signature_valid = <PricePayload<
                <Test as SigningTypes>::Public,
                <Test as frame_system::Config>::BlockNumber
            > as SignedPayload<Test>>::verify::<crypto::OcwAuthId>(&price_payload_b1, signature.clone());
            assert!(signature_valid);
        }
    });

    offchain_state.write().expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/btcusdt".into(),
        response: Some(get_are_json_of_btc().as_bytes().to_vec()),
        sent: true,
        ..Default::default()
    });

    offchain_state.write().expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/ethusdt".into(),
        response: Some(get_are_json_of_eth().as_bytes().to_vec()),
        sent: true,
        ..Default::default()
    });

    offchain_state.write().expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/dotusdt".into(),
        response: Some(get_are_json_of_dot().as_bytes().to_vec()),
        sent: true,
        ..Default::default()
    });
    //
    let price_payload_b2 = PricePayload {
        block_number: 2, // type is BlockNumber
        price: vec![
            // price_key, price_val, fraction_num
            ("btc_price".as_bytes().to_vec(), 502613720u64, 4),
            ("eth_price".as_bytes().to_vec(), 31077100, 4),
            ("dot_price".as_bytes().to_vec(), 359921, 4),
            // (PriceKey::PriceKeyIsXRP, 109),
        ],
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    t.execute_with(|| {
        // when execute blocknumber = 2
        AresOcw::save_fetch_ares_price_and_send_payload_signed(2, <Test as crate::Config>::MaxCountOfPerRequest::get()).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        if let Call::AresOcw(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
            assert_eq!(body.clone(), price_payload_b2);
            let signature_valid = <PricePayload<
                <Test as SigningTypes>::Public,
                <Test as frame_system::Config>::BlockNumber
            > as SignedPayload<Test>>::verify::<crypto::OcwAuthId>(&price_payload_b2, signature.clone());
            assert!(signature_valid);
            // Try to submit on chain
            // AresOcw::submit_price_unsigned_with_signed_payload(Origin::none(),body,signature);
        }
    });
}

#[test]
fn test_request_propose_submit() {
    let mut t = new_test_ext();

    t.execute_with(|| {
        assert_eq!(AresOcw::prices_requests().len(), 4);
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 , 4));
        assert_eq!(AresOcw::prices_requests().len(), 5);

        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 4));

        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://aaa.com"), 3 , 3));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://aaa.com"), 3, 3));
    });
}

#[test]
fn test_request_propose_submit_impact_on_the_price_pool() {
    let mut t = new_test_ext();

    t.execute_with(|| {

        System::set_block_number(3);

        assert_eq!(AresOcw::prices_requests().len(), 4);

        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 , 4));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 4));

        // Add some price
        let price_key = "xxx_price".as_bytes().to_vec();//
        AresOcw::add_price(Default::default(), 8888, price_key.clone(), 4, 100);
        AresOcw::add_price(Default::default(), 7777, price_key.clone(), 4, 100);
        // Get save price
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4), (7777,Default::default(), 3, 4)], btc_price_list);

        // if parse version change
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 8 , 4));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 8, 4));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4), (7777,Default::default(), 3, 4)], btc_price_list);


        // Other price request get in
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("zzz_price"), toVec("http://zzz.com"), 8 , 4));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("zzz_price"), toVec("http://zzz.com"), 8, 4));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4), (7777,Default::default(), 3, 4)], btc_price_list);


        // Other price request fraction number change.
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("zzz_price"), toVec("http://zzz.com"), 8 , 5));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("zzz_price"), toVec("http://zzz.com"), 8, 5));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4), (7777,Default::default(), 3, 4)], btc_price_list);


        // Current price request fraction number change. (xxx_price)
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 , 5));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 5));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        // price will be empty.
        assert_eq!(0, btc_price_list.len());

    });
}

// test construct LocalPriceRequestStorage
#[test]
fn test_rebuild_LocalPriceRequestStorage() {

    // let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"http://141.164.58.241:5566/api/getPartyPrice/btcusdt\",\"parse_version\":1}";
    // let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"\",\"parse_version\":1}";
    //
    // // let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"http://141.164.58.241:5566/api/getPartyPrice/ethusdt\",\"parse_version\":1}";
    // let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"\",\"parse_version\":1}";
    //
    // let target_json = "{\"price_key\":\"dot_price\",\"request_url\":\"http://141.164.58.241:5566/api/getPartyPrice/dotusdt\",\"parse_version\":1}";
    // let target_json = "{\"price_key\":\"dot_price\",\"request_url\":\"\",\"parse_version\":1}";
    //
    // let target_json = "{\"price_key\":\"xrp_price\",\"request_url\":\"http://141.164.58.241:5566/api/getPartyPrice/xrpusdt\",\"parse_version\":1}";
    // let target_json = "{\"price_key\":\"xrp_price\",\"request_url\":\"\",\"parse_version\":1}";

    // let target_json_v8 =target_json.encode();
    // println!("Try : Vec<u8> encode {:?} ", HexDisplay::from(&target_json_v8));

    // let (offchain, state) = testing::TestOffchainExt::new();
    // let mut t = sp_io::TestExternalities::default();

    let mut t = new_test_ext();


    let (offchain, _state) = TestOffchainExt::new();
    let (pool, state) = TestTransactionPoolExt::new();
    t.register_extension(OffchainDbExt::new(offchain.clone()));
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));


    t.execute_with(|| {

        assert_eq!(AresOcw::get_price_source_list(true).len(), 4, "There are 4 group data on the chain.");
        assert_eq!(AresOcw::get_price_source_list(false).len(), 0, "There are 0 group data on the local store.");

        // Test insert new one.
        let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"/api/getPartyPrice/btcusdt\",\"parse_version\":1}";
        let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
        assert_eq!(info.unwrap().len(), 1);

        assert_eq!(AresOcw::get_price_source_list(false).len(), 1);

        // Test insert another.
        let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"/api/getPartyPrice/ethusdt\",\"parse_version\":1}";
        let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
        assert_eq!(info.unwrap().len(), 2);

        assert_eq!(AresOcw::get_price_source_list(false).len(), 2);

        // Test change exists value
        let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"/api/getPartyPrice/btcusdt\",\"parse_version\":2}";
        let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
        assert_eq!(info.clone().unwrap().len(), 2);
        assert_eq!(info.unwrap()[1].parse_version, 2);

        assert_eq!(AresOcw::get_price_source_list(false).len(), 2);

        // Remove eth_price key
        let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"\",\"parse_version\":1}";
        let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
        assert_eq!(info.clone().unwrap().len(), 1);
        assert_eq!(info.unwrap()[0].price_key, "btc_price".as_bytes().to_vec(), "only btc_price in vec!");

        assert_eq!(AresOcw::get_price_source_list(false).len(), 1);
    });
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
    crate::GenesisConfig::<Test>{
        _phantom: Default::default(),
        price_requests: vec![
            (toVec("btc_price"), toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
            (toVec("eth_price"), toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
            (toVec("dot_price"), toVec("/api/getPartyPrice/dotusdt"), 1u32, 4u32),
            (toVec("xrp_price"), toVec("/api/getPartyPrice/xrpusdt"), 1u32, 4u32),
        ]
    }.assimilate_storage(&mut t).unwrap();
    t.into()
}

fn toVec(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}

fn get_are_json_of_btc() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":50261.372,\"timestamp\":1629699168,\"infos\":[{\"price\":50244.79,\"weight\":1,\"exchangeName\":\"binance\"},{\"price\":50243.16,\"weight\":1,\"exchangeName\":\"cryptocompare\"},{\"price\":50274,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":50301.59,\"weight\":1,\"exchangeName\":\"bitstamp\"},{\"price\":50243.32,\"weight\":1,\"exchangeName\":\"huobi\"}]}}"
}

fn get_are_json_of_eth() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":3107.71,\"timestamp\":1630055777,\"infos\":[{\"price\":3107,\"weight\":1,\"exchangeName\":\"huobi\"},{\"price\":3106.56,\"weight\":1,\"exchangeName\":\"cryptocompare\"},{\"price\":3106.68,\"weight\":1,\"exchangeName\":\"ok\"},{\"price\":3107,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":3111.31,\"weight\":1,\"exchangeName\":\"bitstamp\"}]}}"
}

fn get_are_json_of_dot() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":35.9921,\"timestamp\":1631497660,\"infos\":[{\"price\":36.0173,\"weight\":1,\"exchangeName\":\"huobi\"},{\"price\":36.012,\"weight\":1,\"exchangeName\":\"coinbase\"},{\"price\":35.947,\"weight\":1,\"exchangeName\":\"bitfinex\"}]}}"
}

fn get_are_json_of_xrp() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":1.09272,\"timestamp\":1631497987,\"infos\":[{\"price\":1.09319,\"weight\":1,\"exchangeName\":\"huobi\"},{\"price\":1.0922,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":1.09277,\"weight\":1,\"exchangeName\":\"ok\"}]}}"
}

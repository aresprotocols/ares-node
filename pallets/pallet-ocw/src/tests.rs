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
use super::Event as AresOcwEvent;
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
use frame_system::{Phase};
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
use frame_support::traits::{FindAuthor, VerifySeal, Len};
use pallet_authorship::SealVerify;
use sp_staking::SessionIndex;
use sp_runtime::traits::AppVerify;

use frame_system::{EnsureSignedBy, EnsureRoot};
use std::convert::TryInto;
use sp_core::hexdisplay::HexDisplay;
use lite_json::JsonValue::Null;
use frame_support::sp_runtime::traits::IsMember;
use crate::sr25519::AuthorityId;
use sp_application_crypto::Pair;
use frame_support::sp_std::convert::TryFrom;
use frame_support::sp_runtime::app_crypto::Ss58Codec;

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

pub struct TestFindAuthor;
impl FindAuthor<AccountId> for TestFindAuthor {
    fn find_author<'a, I>(digests: I) -> Option<AccountId> where
        I: 'a + IntoIterator<Item=(ConsensusEngineId, &'a [u8])>
    {
        for (id, data) in digests {
            if id == TEST_ID {
                Public::decode(&mut &data[..]).ok();
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
    // pub const PriceVecMaxSize: u32 = 3;
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
    // type ValidatorSet = Historical;
    type RequestOrigin = frame_system::EnsureRoot<AccountId>;
    // type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
    type FindAuthor = TestFindAuthor;
    // type PriceVecMaxSize = PriceVecMaxSize;
    // type MaxCountOfPerRequest = MaxCountOfPerRequest;
    type NeedVerifierCheck = NeedVerifierCheck;
    type UseOnChainPriceRequest = UseOnChainPriceRequest;
    type FractionLengthNum = FractionLengthNum;
    type CalculationKind = CalculationKind;

    type ValidatorAuthority= AccountId;
    type VMember = TestMember;
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TestMember;
impl IsMember<AccountId> for TestMember {
    fn is_member(member_id: &AccountId) -> bool {
        true
    }
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


// #[test]
// fn test_connect_request_url(){
//     let (offchain, _state) = testing::TestOffchainExt::new();
//     let mut t = sp_io::TestExternalities::default();
//     t.register_extension(OffchainWorkerExt::new(offchain));
//
//     t.execute_with(|| {
//         assert_eq!(AresOcw::get_local_storage_request_domain(), "http://127.0.0.1:5566".as_bytes().to_vec());
//         assert_eq!(AresOcw::make_local_storage_request_uri_by_str("/get/price1"), "http://127.0.0.1:5566/get/price1".as_bytes().to_vec());
//         assert_eq!(AresOcw::make_local_storage_request_uri_by_vec_u8("/get/price2".as_bytes().to_vec()), "http://127.0.0.1:5566/get/price2".as_bytes().to_vec());
//     });
// }

#[test]
fn addprice_of_ares () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    // let mut t = sp_io::TestExternalities::default();
    let mut t = new_test_ext();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {
        // The request key must be configured, otherwise you cannot submit the price. so you need => new_test_ext()

        System::set_block_number(1);
        // when
        let price_key = "btc_price".as_bytes().to_vec();// PriceKey::PriceKeyIsBTC ;
        AresOcw::add_price(Default::default(), 8888, price_key.clone(), 4, Default::default() ,2);
        AresOcw::add_price(Default::default(), 9999, price_key.clone(), 4, Default::default(), 2);

        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        // (price_val, accountid, block_num, fraction_num, json_number_value)
        // assert_eq!(vec![(8888,Default::default(), 1, 4, Default::default()), (9999,Default::default(), 1, 4, Default::default())], btc_price_list);
        assert_eq!(0, btc_price_list.len(), "Price list will be empty when the average calculation.");

        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((8888 + 9999) /2, 4) , "Only test ares_avg_prices ");

        // Add a new value beyond the array boundary.
        AresOcw::add_price(Default::default(), 3333, price_key.clone(), 4, Default::default(), 2);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());

        // (price_val, accountid, block_num, fraction_num)
        assert_eq!(vec![(3333, Default::default(), 1, 4, Default::default())], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((8888 + 9999) / 2, 4));

        // when
        let price_key = "eth_price".as_bytes().to_vec() ;// PriceKey::PriceKeyIsETH ;
        AresOcw::add_price(Default::default(), 7777, price_key.clone(), 4, Default::default(), 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        // (price_val, accountid, block_num, fraction_num)
        assert_eq!(vec![(7777, Default::default(), 1, 4, Default::default())], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (0, 0), "Price pool is not full.");

        AresOcw::add_price(Default::default(), 6666, price_key.clone(), 4, Default::default(), 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(0, btc_price_list.len());

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((7777 + 6666) / 2, 4));

        //
        AresOcw::add_price(Default::default(), 1111, price_key.clone(), 4, Default::default(), 2);
        let btc_price_list = AresOcw::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(1111, Default::default(), 1, 4, Default::default())], btc_price_list);

        let bet_avg_price = AresOcw::ares_avg_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((7777 + 6666) / 2, 4));

    });
}


#[test]
fn test_abnormal_price_despose () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    // let mut t = sp_io::TestExternalities::default();
    let mut t = new_test_ext();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {

        let BN:u64 = 2;
        System::set_block_number(BN);

        // In the genesis config default pool depth is 3.
        assert_eq!(3, AresOcw::get_price_pool_depth());

        let price_key = "btc_price".as_bytes().to_vec();

        // Test normal price list, Round 1
        AresOcw::add_price(Default::default(), 1000, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 1010, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(2 as usize, AresOcw::ares_prices(price_key.clone()).len());
        AresOcw::add_price(Default::default(), 1020, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(0 as usize, AresOcw::ares_prices(price_key.clone()).len(), "The price pool is cleared after full.");
        let bet_avg_price = AresOcw::ares_avg_prices(price_key.clone());
        assert_eq!(bet_avg_price, (1010, 4));


        // Test normal price list, Round 2
        AresOcw::add_price(Default::default(), 1030, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(1 as usize, AresOcw::ares_prices(price_key.clone()).len());
        AresOcw::add_price(Default::default(), 1040, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(2 as usize, AresOcw::ares_prices(price_key.clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices(price_key.clone());
        assert_eq!(bet_avg_price, (1010, 4), "If the price pool not full, the average price is old value.");
        // Add a new one price pool is full, the average price will be update.
        AresOcw::add_price(Default::default(), 1010, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        // Check price pool.
        assert_eq!(0 as usize, AresOcw::ares_prices(price_key.clone()).len(), "The price pool is cleared after full.");
        let bet_avg_price = AresOcw::ares_avg_prices(price_key.clone());
        assert_eq!(bet_avg_price, (1030, 4));

        // Test abnormal price list, Round 3
        AresOcw::add_price(Default::default(), 1020, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(1 as usize, AresOcw::ares_prices(price_key.clone()).len());
        AresOcw::add_price(Default::default(), 1030, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(2 as usize, AresOcw::ares_prices(price_key.clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices(price_key.clone());
        assert_eq!(bet_avg_price, (1030, 4), "If the price pool not full, the average price is old value.");
        // Add a new one price pool is full, the average price will be update.
        AresOcw::add_price(Default::default(), 2000, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        // Check price pool.
        assert_eq!(0 as usize, AresOcw::ares_prices(price_key.clone()).len(), "The price pool is cleared after full.");
        let bet_avg_price = AresOcw::ares_avg_prices(price_key.clone());
        assert_eq!(bet_avg_price, ((1030 + 1020)/2 , 4));

        // Check abnormal price list.
        assert_eq!(1 as usize, AresOcw::ares_abnormal_prices(price_key.clone()).len());
        // price, account, bolcknumber, FractionLength, JsonNumberValue
        // Vec<(u64, T::AccountId, T::BlockNumber, FractionLength, JsonNumberValue)>,
        assert_eq!(vec![(2000, Default::default(), BN, 4, Default::default())], AresOcw::ares_abnormal_prices(price_key.clone()));


    });
}

#[test]
fn test_get_price_pool_depth () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    // let mut t = sp_io::TestExternalities::default();
    let mut t = new_test_ext();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {

        // let BN:u64 = 2;
        // System::set_block_number(BN);

        // In the genesis config default pool depth is 3.
        assert_eq!(3, AresOcw::get_price_pool_depth());

        // Test input some price
        let price_key = "btc_price".as_bytes().to_vec();
        AresOcw::add_price(Default::default(), 6660, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 8880, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (0, 0));
        AresOcw::add_price(Default::default(), 7770, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(0 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        // Why price is 7770 , Because average value is 7770 :
        // and (7770 - 6660) * 100 / 7770 = 14 , pick out 6660
        // and (8880 - 7770) * 100 / 7770 = 14 , pick out 8880
        // and (7770 - 7770) * 100 / 7770 = 0
        assert_eq!(bet_avg_price, (7770, 4));
        assert_eq!(2 as usize, AresOcw::ares_abnormal_prices("btc_price".as_bytes().to_vec()).len());

        // Update depth to 5
        // if parse version change
        assert_ok!(AresOcw::pool_depth_propose(Origin::root(), 5));
        assert_eq!(5, AresOcw::get_price_pool_depth());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (7770, 4), " Pool expansion, but average has not effect.");

        AresOcw::add_price(Default::default(), 5550, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 6660, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(2 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (7770, 4), "Old value yet.");

        // fill price list.
        AresOcw::add_price(Default::default(), 5350, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 5500, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 5400, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(0 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, ((5550+5350+5500+5400)/4, 4), "Average update.");

        // Fall back depth to 3
        assert_ok!(AresOcw::pool_depth_propose(Origin::root(), 3));
        AresOcw::add_price(Default::default(), 4440, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(3, AresOcw::get_price_pool_depth());
        assert_eq!(1 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len());
        AresOcw::add_price(Default::default(), 4430, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 4420, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(0 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (4430, 4));
        //
        AresOcw::add_price(Default::default(), 4440, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        AresOcw::add_price(Default::default(), 4440, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        assert_eq!(2 as usize, AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone()).len(), "Should 4440");
        AresOcw::add_price(Default::default(), 4340, price_key.clone(), 4, Default::default(), AresOcw::get_price_pool_depth());
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (4440, 4));
    });
}

#[test]
fn test_json_number_value_to_price () {
    // number =
    let number1 = JsonNumberValue {
        integer: 8,
        fraction: 87654,
        fraction_length: 5,
        exponent: 0
    };
    assert_eq!(8876540 , number1.toPrice(6));
    assert_eq!(887654 , number1.toPrice(5));
    assert_eq!(88765 , number1.toPrice(4));
    assert_eq!(8876 , number1.toPrice(3));
    assert_eq!(887 , number1.toPrice(2));
    assert_eq!(88 , number1.toPrice(1));
    assert_eq!(8 , number1.toPrice(0));

    let number3 = JsonNumberValue {
        integer: 6,
        fraction: 654,
        fraction_length: 3,
        exponent: 0
    };
    assert_eq!(6654000 , number3.toPrice(6));
    assert_eq!(665400 , number3.toPrice(5));
    assert_eq!(66540 , number3.toPrice(4));
    assert_eq!(6654 , number3.toPrice(3));
    assert_eq!(665 , number3.toPrice(2));
    assert_eq!(66 , number3.toPrice(1));
    assert_eq!(6 , number3.toPrice(0));

}

#[test]
fn test_request_price_update_then_the_price_list_will_be_update_if_the_fractioin_length_changed () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    // let mut t = sp_io::TestExternalities::default();
    let mut t = new_test_ext();
    t.register_extension(OffchainWorkerExt::new(offchain));

    t.execute_with(|| {

        let BN:u64 = 2;
        System::set_block_number(BN);

        // number =
        let number1 = JsonNumberValue {
            integer: 8,
            fraction: 87654,
            fraction_length: 5,
            exponent: 0
        };
        let number2 = JsonNumberValue {
            integer: 8,
            fraction: 76543,
            fraction_length: 5,
            exponent: 0
        };
        let number3 = JsonNumberValue {
            integer: 8,
            fraction: 654,
            fraction_length: 3,
            exponent: 0
        };


        // when
        let price_key = "btc_price".as_bytes().to_vec();// PriceKey::PriceKeyIsBTC ;
        AresOcw::add_price(Default::default(), number1.toPrice(4), price_key.clone(), 4, number1.clone(), 4);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(number1.toPrice(4), Default::default(), BN, 4, number1.clone())], btc_price_list);
        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(bet_avg_price, (0, 0));

        AresOcw::add_price(Default::default(), number2.toPrice(4), price_key.clone(), 4, number2.clone(), 4);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(number1.toPrice(4),Default::default(), BN, 4, number1.clone()), (number2.toPrice(4),Default::default(), BN, 4, number2.clone())], btc_price_list);

        // When fraction length change, list will be update new fraction.
        AresOcw::add_price(Default::default(), number3.toPrice(3), price_key.clone(), 3, number3.clone(), 4);
        let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![
                        (number1.toPrice(3),Default::default(), BN, 3, number1.clone()),
                        (number2.toPrice(3),Default::default(), BN, 3, number2.clone()),
                        (number3.toPrice(3),Default::default(), BN, 3, number3.clone()),
                    ], btc_price_list);


        AresOcw::add_price(Default::default(), number1.toPrice(5), price_key.clone(), 5, number1.clone(), 4);
        let abnormal_vec = AresOcw::ares_abnormal_prices("btc_price".as_bytes().to_vec());
        assert_eq!(0, abnormal_vec.len());

        let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        // assert_eq!(bet_avg_price, (0, 0));
        assert_eq!(bet_avg_price, ((
                                       number1.toPrice(5) + number2.toPrice(5)
                                   ) / 2, 5));


        // let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        // assert_eq!(bet_avg_price, ((number1.toPrice(4) + number2.toPrice(4)) / 2, 4));
        //
        // // then fraction changed, old price list will be update to new fraction length.
        // AresOcw::add_price(Default::default(), number3.toPrice(3), price_key.clone(), 3, number3.clone(), 2);
        // let btc_price_list = AresOcw::ares_prices("btc_price".as_bytes().to_vec().clone());
        // assert_eq!(vec![ (number2.toPrice(3),Default::default(), BN, 3, number2.clone()),
        //                  (number3.toPrice(3), Default::default(), BN, 3, number3.clone())
        //                 ], btc_price_list);
        // let bet_avg_price = AresOcw::ares_avg_prices("btc_price".as_bytes().to_vec().clone());
        // // assert_eq!(bet_avg_price, (0, 0));
        // assert_eq!(bet_avg_price, ((
        //                             number2.toPrice(3) +
        //                             number3.toPrice(3)
        //                            ) / 2, 3));
    });
}

#[test]
fn bulk_parse_price_ares_works() {

    let FRACTION_NUM_2:u32 = 2 ;
    let FRACTION_NUM_3:u32 = 3 ;
    let FRACTION_NUM_4:u32 = 4 ;
    let FRACTION_NUM_5:u32 = 5 ;
    let FRACTION_NUM_6:u32 = 6 ;

    // Bulk parse
    // defined parse format
    let mut format = Vec::new();
    format.push((toVec("btc_price"), toVec("btcusdt"), FRACTION_NUM_2));
    format.push((toVec("eth_price"), toVec("ethusdt"), FRACTION_NUM_3));
    format.push((toVec("dot_price"), toVec("dotusdt"), FRACTION_NUM_4));
    format.push((toVec("xrp_price"), toVec("xrpusdt"), FRACTION_NUM_5));
    // xxx_price not exist, so what up ?
    format.push((toVec("xxx_price"), toVec("xxxusdt"), FRACTION_NUM_6));

    let result_bulk_parse = AresOcw::bulk_parse_price_of_ares(get_are_json_of_bulk(), format);

    let test_number_value = NumberValue {
        integer: 0,
        fraction: 0,
        fraction_length: 0,
        exponent: 0
    };

    let mut bulk_expected = Vec::new();
    bulk_expected.push((toVec("btc_price"), Some(5026137), FRACTION_NUM_2, NumberValue {
        integer: 50261,
        fraction: 372,
        fraction_length: 3,
        exponent: 0
    }));
    bulk_expected.push((toVec("eth_price"), Some(3107710), FRACTION_NUM_3, NumberValue {
        integer: 3107,
        fraction: 71,
        fraction_length: 2,
        exponent: 0
    }));
    bulk_expected.push((toVec("dot_price"), Some(359921), FRACTION_NUM_4, NumberValue {
        integer: 35,
        fraction: 9921,
        fraction_length: 4,
        exponent: 0
    }));
    bulk_expected.push((toVec("xrp_price"), Some(109272), FRACTION_NUM_5, NumberValue {
        integer: 1,
        fraction: 9272,
        fraction_length: 5,
        exponent: 0
    }));

    // println!("!!!!!!!!{:?}", result_bulk_parse);

    assert_eq!(result_bulk_parse, bulk_expected);


    // The above looks normal. Next, test the return value of 0

    // Bulk parse
    // defined parse format
    let mut format = Vec::new();
    format.push((toVec("btc_price"), toVec("btcusdt"), FRACTION_NUM_2));
    format.push((toVec("eth_price"), toVec("ethusdt"), FRACTION_NUM_3));
    format.push((toVec("dot_price"), toVec("dotusdt"), FRACTION_NUM_4));
    format.push((toVec("xrp_price"), toVec("xrpusdt"), FRACTION_NUM_5));
    // xxx_price not exist, so what up ?
    format.push((toVec("xxx_price"), toVec("xxxusdt"), FRACTION_NUM_6));

    let result_bulk_parse = AresOcw::bulk_parse_price_of_ares(get_are_json_of_bulk_of_xxxusdt_is_0(), format);

    let mut bulk_expected = Vec::new();
    bulk_expected.push((toVec("btc_price"), Some(5026137), FRACTION_NUM_2, NumberValue {
        integer: 50261,
        fraction: 372,
        fraction_length: 3,
        exponent: 0
    }));
    bulk_expected.push((toVec("eth_price"), Some(3107710), FRACTION_NUM_3, NumberValue {
        integer: 3107,
        fraction: 71,
        fraction_length: 2,
        exponent: 0
    }));
    bulk_expected.push((toVec("dot_price"), Some(359921), FRACTION_NUM_4, NumberValue {
        integer: 35,
        fraction: 9921,
        fraction_length: 4,
        exponent: 0
    }));
    bulk_expected.push((toVec("xrp_price"), Some(109272), FRACTION_NUM_5, NumberValue {
        integer: 1,
        fraction: 9272,
        fraction_length: 5,
        exponent: 0
    }));

    assert_eq!(result_bulk_parse, bulk_expected);
}

// This test will be discarded.
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
}

#[test]
fn test_get_raw_price_source_list () {
    let mut t = new_test_ext();
    let (offchain, state) = testing::TestOffchainExt::new();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.execute_with(|| {
        let raw_price_source_list = AresOcw::get_raw_price_source_list(true);
        println!("raw_price_source_list = {:?}", raw_price_source_list);
    });
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
        uri: "http://127.0.0.1:5566/api/getPartyPrice/btcusdt".into(),
        response: Some(json_response),
        sent: true,
        ..Default::default()
    });

    t.execute_with(|| {
        let price = AresOcw::fetch_price_body_with_http(Vec::new(), "http://127.0.0.1:5566/api/getPartyPrice/btcusdt", 1u32, 2).unwrap();
        assert_eq!(price, 5026137);
    });
}


// #[test]
// fn test_format_request_data() {
//     let mut t = new_test_ext();
//
//     let request_list = vec![
//         (toVec("btc_price"), toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
//         (toVec("eth_price"), toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
//         (toVec("dot_price"), toVec("/api/getPartyPrice/dotusdt"), 1u32, 4u32),
//         (toVec("xrp_price"), toVec("/api/getPartyPrice/xrpusdt"), 1u32, 4u32),
//     ];
//
//     let result_request_list = vec![
//         (vec![toVec("btc_price")], toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
//         (vec![toVec("eth_price")], toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
//         (vec![toVec("dot_price")], toVec("/api/getPartyPrice/dotusdt"), 1u32, 4u32),
//         (vec![toVec("xrp_price")], toVec("/api/getPartyPrice/xrpusdt"), 1u32, 4u32),
//     ];
//
//     t.execute_with(|| {
//         let formated_request_list = AresOcw::format_request_data(request_list).unwrap();
//         assert_eq!(formated_request_list, result_request_list);
//     });
//
//     let request_list = vec![
//         (toVec("btc_price"), toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
//         (toVec("eth_price"), toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
//         (toVec("dot_price"), toVec("/api/getBulkPrices"), 2u32, 5u32),
//         (toVec("xrp_price"), toVec("/api/getBulkPrices"), 2u32, 3u32),
//     ];
//
//     let result_request_list = vec![
//         (toVec("btc_price"), toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
//         (toVec("eth_price"), toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
//         (toVec("dot_price"), toVec("/api/getBulkPrices"), 2u32, 5u32),
//         (toVec("xrp_price"), toVec("/api/getBulkPrices"), 2u32, 3u32),
//     ];
//
//     t.execute_with(|| {
//         let formated_request_list = AresOcw::format_request_data(request_list).unwrap();
//         assert_eq!(formated_request_list, request_list);
//     });
// }

#[test]
fn test_make_bulk_price_format_data () {
    let mut t = new_test_ext();

    let (offchain, state) = testing::TestOffchainExt::new();
    t.register_extension(OffchainWorkerExt::new(offchain));

    let mut expect_format = Vec::new();
    expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));

    t.execute_with(|| {
        let price_format = AresOcw::make_bulk_price_format_data(1);
        assert_eq!(expect_format, price_format);
    });

    // When block number is 2
    let mut expect_format = Vec::new();
    expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
    expect_format.push(("eth_price".as_bytes().to_vec(), "ethusdt".as_bytes().to_vec(), 4));
    t.execute_with(|| {
        let price_format = AresOcw::make_bulk_price_format_data(2);
        assert_eq!(expect_format, price_format);
    });

    // When block number is 3
    let mut expect_format = Vec::new();
    expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
    expect_format.push(("dot_price".as_bytes().to_vec(), "dotusdt".as_bytes().to_vec(), 4));
    t.execute_with(|| {
        let price_format = AresOcw::make_bulk_price_format_data(3);
        assert_eq!(expect_format, price_format);
    });

    // When block number is 4
    let mut expect_format = Vec::new();
    expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
    expect_format.push(("eth_price".as_bytes().to_vec(), "ethusdt".as_bytes().to_vec(), 4));
    expect_format.push(("xrp_price".as_bytes().to_vec(), "xrpusdt".as_bytes().to_vec(), 4));
    t.execute_with(|| {
        let price_format = AresOcw::make_bulk_price_format_data(4);
        assert_eq!(expect_format, price_format);
    });

    // When block number is 5
    let mut expect_format = Vec::new();
    expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
    t.execute_with(|| {
        let price_format = AresOcw::make_bulk_price_format_data(1);
        assert_eq!(expect_format, price_format);
    });

}

#[test]
fn make_bulk_price_request_url () {

    let mut t = new_test_ext();
    t.execute_with(|| {
        let mut expect_format = Vec::new();
        expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
        expect_format.push(("eth_price".as_bytes().to_vec(), "ethusdt".as_bytes().to_vec(), 4));

        let bulk_request = AresOcw::make_bulk_price_request_url(expect_format);
        assert_eq!("http://127.0.0.1:5566/api/getBulkPrices?symbol=btcusdt_ethusdt".as_bytes().to_vec(), bulk_request);

        let mut expect_format = Vec::new();
        expect_format.push(("btc_price".as_bytes().to_vec(), "btcusdt".as_bytes().to_vec(), 4));
        expect_format.push(("eth_price".as_bytes().to_vec(), "ethusdt".as_bytes().to_vec(), 4));
        expect_format.push(("btc_price".as_bytes().to_vec(), "dotusdt".as_bytes().to_vec(), 4));
        expect_format.push(("eth_price".as_bytes().to_vec(), "xrpusdt".as_bytes().to_vec(), 4));

        let bulk_request = AresOcw::make_bulk_price_request_url(expect_format);
        assert_eq!("http://127.0.0.1:5566/api/getBulkPrices?symbol=btcusdt_ethusdt_dotusdt_xrpusdt".as_bytes().to_vec(), bulk_request);
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
        // uri: "http://127.0.0.1:5566/api/getBulkPrices?symbol=btcusdt_ethusdt_dotusdt_xrpusdt".into(),
        uri: "http://127.0.0.1:5566/api/getBulkPrices?symbol=btcusdt".into(),
        response: Some(get_are_json_of_bulk().as_bytes().to_vec()),
        sent: true,
        ..Default::default()
    };

    offchain_state.write().expect_request(padding_request);

    let price_payload_b1 = PricePayload {
        block_number: 1, // type is BlockNumber
        price: vec![
            ("btc_price".as_bytes().to_vec(), 502613720u64, 4, JsonNumberValue{
                integer: 50261,
                fraction: 372,
                fraction_length: 3,
                exponent: 0
            }),
            // ("eth_price".as_bytes().to_vec(), 31077100, 4),
            // ("dot_price".as_bytes().to_vec(), 359921, 4),
            // ("xrp_price".as_bytes().to_vec(), 10927, 4),
        ],
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    // println!("RUN 1 -------------");
    // assert_eq!(3, <Test as crate::Config>::MaxCountOfPerRequest::get(), "Current use MaxCount is 3");

    // let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
    t.execute_with(|| {

        // price_payload_b1.sign::


        // when execute blocknumber = 1
        // <Test as crate::Config>::MaxCountOfPerRequest::get() will be del.
        AresOcw::save_fetch_ares_price_and_send_payload_signed(1).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        if let Call::AresOcw(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
            println!("signature = {:?}", signature);
            assert_eq!(body.clone(), price_payload_b1);
            let signature_valid = <PricePayload<
                <Test as SigningTypes>::Public,
                <Test as frame_system::Config>::BlockNumber
            > as SignedPayload<Test>>::verify::<crypto::OcwAuthId>(&price_payload_b1, signature.clone());
            assert!(signature_valid);
        }
    });

    // offchain_state.write().expect_request(testing::PendingRequest {
    //     method: "GET".into(),
    //     uri: "http://127.0.0.1:5566/api/getPartyPrice/btcusdt".into(),
    //     response: Some(get_are_json_of_btc().as_bytes().to_vec()),
    //     sent: true,
    //     ..Default::default()
    // });
    //
    // offchain_state.write().expect_request(testing::PendingRequest {
    //     method: "GET".into(),
    //     uri: "http://127.0.0.1:5566/api/getPartyPrice/ethusdt".into(),
    //     response: Some(get_are_json_of_eth().as_bytes().to_vec()),
    //     sent: true,
    //     ..Default::default()
    // });
    //
    // offchain_state.write().expect_request(testing::PendingRequest {
    //     method: "GET".into(),
    //     uri: "http://127.0.0.1:5566/api/getPartyPrice/dotusdt".into(),
    //     response: Some(get_are_json_of_dot().as_bytes().to_vec()),
    //     sent: true,
    //     ..Default::default()
    // });
    // //
    // let price_payload_b2 = PricePayload {
    //     block_number: 2, // type is BlockNumber
    //     price: vec![
    //         // price_key, price_val, fraction_num
    //         ("btc_price".as_bytes().to_vec(), 502613720u64, 4),
    //         ("eth_price".as_bytes().to_vec(), 31077100, 4),
    //         ("dot_price".as_bytes().to_vec(), 359921, 4),
    //         // (PriceKey::PriceKeyIsXRP, 109),
    //     ],
    //     public: <Test as SigningTypes>::Public::from(public_key),
    // };
    //
    // t.execute_with(|| {
    //     // when execute blocknumber = 2
    //     AresOcw::save_fetch_ares_price_and_send_payload_signed(2, <Test as crate::Config>::MaxCountOfPerRequest::get()).unwrap();
    //     // then
    //     let tx = pool_state.write().transactions.pop().unwrap();
    //     let tx = Extrinsic::decode(&mut &*tx).unwrap();
    //     assert_eq!(tx.signature, None);
    //     if let Call::AresOcw(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
    //         assert_eq!(body.clone(), price_payload_b2);
    //         let signature_valid = <PricePayload<
    //             <Test as SigningTypes>::Public,
    //             <Test as frame_system::Config>::BlockNumber
    //         > as SignedPayload<Test>>::verify::<crypto::OcwAuthId>(&price_payload_b2, signature.clone());
    //         assert!(signature_valid);
    //         // Try to submit on chain
    //         // AresOcw::submit_price_unsigned_with_signed_payload(Origin::none(),body,signature);
    //     }
    // });
}

#[test]
fn test_allowable_offset_propose() {
    let mut t = new_test_ext();
    t.execute_with(|| {
        assert_eq!(AresOcw::price_allowable_offset(), 10);
        assert_ok!(AresOcw::allowable_offset_propose(Origin::root(), 20));
        assert_eq!(AresOcw::price_allowable_offset(), 20);
    });
}

// mod app {
//     use sp_application_crypto::{
//         key_types::AUTHORITY_DISCOVERY,
//         app_crypto,
//         sr25519,
//     };
//     app_crypto!(sr25519, AUTHORITY_DISCOVERY);
// }
// sp_application_crypto::with_pair! {
// 	/// An authority discovery authority keypair.
// 	pub type AuthorityPair = app::Pair + sp_application_crypto::Pair;
// }
//
#[test]
fn test_self ( ) {

    use sp_application_crypto::sr25519;
    use sp_runtime::MultiSignature;
    use sp_runtime::MultiSigner;

    // sp_core::sr25519::Pair(schnorrkel::Keypair).;

    // let result = AuthorityPair::verify(signature.into(), signature.into(), test_address.into());
    // assert!(result, "Result is true.")

    let msg = &b"test-message"[..];
    let (pair, _) = sr25519::Pair::generate();

    let signature = pair.sign(&msg);
    assert!(sr25519::Pair::verify(&signature, msg, &pair.public()));

    println!("msg = {:?}", &msg);
    println!("signature = {:?}", &signature);
    println!("pair.public() = {:?}", &pair.public());
    // println!("multi_signer.into_account() = {:?}", &multi_signer.into_account());


    let multi_sig = MultiSignature::from(signature); // OK
    let multi_signer = MultiSigner::from(pair.public());
    assert!(multi_sig.verify(msg, &multi_signer.into_account()));

    let multi_signer = MultiSigner::from(pair.public());
    assert!(multi_sig.verify(msg, &multi_signer.into_account()));

    //---------


    let test_signature = &hex::decode("2aeaa98e26062cf65161c68c5cb7aa31ca050cb5bdd07abc80a475d2a2eebc7b7a9c9546fbdff971b29419ddd9982bf4148c81a49df550154e1674a6b58bac84").expect("Hex invalid")[..];
    let signature = Signature::try_from(test_signature);
    let signature = signature.unwrap();
    println!(" signature = {:?}", signature);
    let account_result =  AccountId::from_ss58check("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");

    let account_id = account_result.unwrap();
    println!(" account_id = {:?} ", account_id);
    let public_id = Public::from_ss58check("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
    let public_id = public_id.unwrap();
    println!(" public_id = {:?} ", public_id);

    let multi_sig = MultiSignature::from(signature); // OK
    let multi_signer = MultiSigner::from(public_id);
    assert!(multi_sig.verify("This is a text message".as_bytes(), &multi_signer.into_account()));

    // let account_encode =  "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".encode();
    // println!(" account = {:?}, {:?}", &account_encode, account_encode.len());

    // let signedMessage_u8 = "This is a text message".as_bytes();
    // let signature_u8 = &hex::decode("0x2aeaa98e26062cf65161c68c5cb7aa31ca050cb5bdd07abc80a475d2a2eebc7b7a9c9546fbdff971b29419ddd9982bf4148c81a49df550154e1674a6b58bac84");// .as_bytes();
    //
    // let test_address_u8 = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".as_bytes();
    //
    // let signature = Signature::try_from(signature_u8);
    // let signature = signature.unwrap();
    // println!(" signature = {:?}", signature);

    // let mut a =[0u8; 64];
    // a[..].copy_from_slice(&signature);
    // let multi_sig = MultiSignature::from(Signature(a));

    //
    // let multi_signer = MultiSigner::from(pair.public());
}

#[test]
fn test_request_propose_submit_and_revoke_propose() {
    let mut t = new_test_ext();

    t.execute_with(|| {
        assert_eq!(AresOcw::prices_requests().len(), 4);
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 , 4, 1));
        assert_eq!(AresOcw::prices_requests().len(), 5);

        //TODO:: test not attach.
        // System::assert_last_event(tests::Event::AresOcw(AresOcwEvent::AddPriceRequest(toVec("xxx_price"), toVec("http://xxx.com"), 2, 4)));

        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 4, 1));

        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://aaa.com"), 3 , 3, 2));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        // price_key are same will be update .
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://aaa.com"), 3, 3, 2));


        // Test revoke.
        assert_ok!(AresOcw::revoke_request_propose(Origin::root(), "xxx_price".as_bytes().to_vec()));
        assert_eq!(AresOcw::prices_requests().len(), 4);
        let tmp_result = AresOcw::prices_requests();
        // price_key are same will be update .
        // println!("== {:?}", sp_std::str::from_utf8( &tmp_result[3].1) );
        assert_eq!(tmp_result[3], (toVec("xrp_price"), toVec("xrpusdt"), 2, 4, 4));


    });
}

#[test]
fn test_request_propose_submit_impact_on_the_price_pool() {
    let mut t = new_test_ext();

    t.execute_with(|| {

        System::set_block_number(3);

        assert_eq!(AresOcw::prices_requests().len(), 4);

        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 , 4, 1));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 4, 1));

        // Add some price
        let price_key = "xxx_price".as_bytes().to_vec();//
        AresOcw::add_price(Default::default(), 8888, price_key.clone(), 4, Default::default(), 100);
        AresOcw::add_price(Default::default(), 7777, price_key.clone(), 4, Default::default(), 100);
        // Get save price
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4, Default::default()), (7777,Default::default(), 3, 4, Default::default())], btc_price_list);

        // if parse version change
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 8 , 4, 1));
        assert_eq!(AresOcw::prices_requests().len(), 5);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[4], (toVec("xxx_price"), toVec("http://xxx.com"), 8, 4, 1));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4, Default::default()), (7777,Default::default(), 3, 4, Default::default())], btc_price_list);

        // Other price request get in
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("zzz_price"), toVec("http://zzz.com"), 8 , 4, 1));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("zzz_price"), toVec("http://zzz.com"), 8, 4, 1));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4, Default::default()), (7777,Default::default(), 3, 4, Default::default())], btc_price_list);

        // Other price request fraction number change.
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("zzz_price"), toVec("http://zzz.com"), 8 , 5, 1));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("zzz_price"), toVec("http://zzz.com"), 8, 5, 1));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        assert_eq!(vec![(8888,Default::default(), 3, 4, Default::default()), (7777,Default::default(), 3, 4, Default::default())], btc_price_list);

        // Current price request fraction number change. (xxx_price)
        assert_ok!(AresOcw::request_propose(Origin::root(), toVec("xxx_price"), toVec("http://xxx.com"), 2 ,5 ,1));
        assert_eq!(AresOcw::prices_requests().len(), 6);
        let tmp_result = AresOcw::prices_requests();
        assert_eq!(tmp_result[5], (toVec("xxx_price"), toVec("http://xxx.com"), 2, 5, 1));
        // Get old price list, Unaffected
        let btc_price_list = AresOcw::ares_prices("xxx_price".as_bytes().to_vec().clone());
        // price will be empty.
        assert_eq!(0, btc_price_list.len());

    });
}

#[test]
fn test_rpc_request () {


    // "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\": \"offchain_localStorageSet\", \"params\":[\"PERSISTENT\", \
    // "0x746172652d6f63773a3a70726963655f726571756573745f646f6d61696e\", \"0x68687474703a2f2f3134312e3136342e35382e3234313a35353636\"]}"

    // Try title : Vec<u8> encode 746172652d6f63773a3a70726963655f726571756573745f646f6d61696e
    // Try body : Vec<u8> encode 68687474703a2f2f3134312e3136342e35382e3234313a35353636
    //                             687474703a2f2f3134312e3136342e35382e3234313a35353838

    let target_json = "are-ocw::price_request_domain";
    let target_json_v8 =target_json.encode();
    println!("Try title : Vec<u8> encode {:?} ", HexDisplay::from(&target_json_v8));

    let target_json = "http://127.0.0.1:5566";
    let target_json_v8 =target_json.encode();
    println!("Try body : Vec<u8> encode {:?} ", HexDisplay::from(&target_json_v8));

    // let target_json = "are-ocw::make_price_request_pool";
    // println!("Old title : Vec<u8> encode {:?} ", HexDisplay::from(target_json));


    assert!(true);
}

// test construct LocalPriceRequestStorage
// TODO::Test is out of date, but it's best not to delete it.
// #[test]
// fn test_rebuild_LocalPriceRequestStorage() {
//
//     // let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"http://127.0.0.1:5566/api/getPartyPrice/btcusdt\",\"parse_version\":1}";
//     // let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"\",\"parse_version\":1}";
//     //
//     // // let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"http://127.0.0.1:5566/api/getPartyPrice/ethusdt\",\"parse_version\":1}";
//     // let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"\",\"parse_version\":1}";
//     //
//     // let target_json = "{\"price_key\":\"dot_price\",\"request_url\":\"http://127.0.0.1:5566/api/getPartyPrice/dotusdt\",\"parse_version\":1}";
//     // let target_json = "{\"price_key\":\"dot_price\",\"request_url\":\"\",\"parse_version\":1}";
//     //
//     // let target_json = "{\"price_key\":\"xrp_price\",\"request_url\":\"http://127.0.0.1:5566/api/getPartyPrice/xrpusdt\",\"parse_version\":1}";
//     // let target_json = "{\"price_key\":\"xrp_price\",\"request_url\":\"\",\"parse_version\":1}";
//
//     let target_json_v8 =target_json.encode();
//     // println!("Try : Vec<u8> encode {:?} ", HexDisplay::from(&target_json_v8));
//
//     // let (offchain, state) = testing::TestOffchainExt::new();
//     // let mut t = sp_io::TestExternalities::default();
//
//     let mut t = new_test_ext();
//
//
//     let (offchain, _state) = TestOffchainExt::new();
//     let (pool, state) = TestTransactionPoolExt::new();
//     t.register_extension(OffchainDbExt::new(offchain.clone()));
//     t.register_extension(OffchainWorkerExt::new(offchain));
//     t.register_extension(TransactionPoolExt::new(pool));
//
//
//     t.execute_with(|| {
//
//         assert_eq!(AresOcw::get_price_source_list(true).len(), 4, "There are 4 group data on the chain.");
//         assert_eq!(AresOcw::get_price_source_list(false).len(), 0, "There are 0 group data on the local store.");
//
//         // Test insert new one.
//         let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"/api/getPartyPrice/btcusdt\",\"parse_version\":1}";
//         let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
//         assert_eq!(info.unwrap().len(), 1);
//
//         assert_eq!(AresOcw::get_price_source_list(false).len(), 1);
//
//         // Test insert another.
//         let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"/api/getPartyPrice/ethusdt\",\"parse_version\":1}";
//         let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
//         assert_eq!(info.unwrap().len(), 2);
//
//         assert_eq!(AresOcw::get_price_source_list(false).len(), 2);
//
//         // Test change exists value
//         let target_json = "{\"price_key\":\"btc_price\",\"request_url\":\"/api/getPartyPrice/btcusdt\",\"parse_version\":2}";
//         let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
//         assert_eq!(info.clone().unwrap().len(), 2);
//         assert_eq!(info.unwrap()[1].parse_version, 2);
//
//         assert_eq!(AresOcw::get_price_source_list(false).len(), 2);
//
//         // Remove eth_price key
//         let target_json = "{\"price_key\":\"eth_price\",\"request_url\":\"\",\"parse_version\":1}";
//         let info: Result<Vec<LocalPriceRequestStorage>, ()>  = AresOcw::update_local_price_storage(&target_json);
//         assert_eq!(info.clone().unwrap().len(), 1);
//         assert_eq!(info.unwrap()[0].price_key, "btc_price".as_bytes().to_vec(), "only btc_price in vec!");
//
//         assert_eq!(AresOcw::get_price_source_list(false).len(), 1);
//     });
// }

// // Old will be discarded.
// pub fn new_test_ext() -> sp_io::TestExternalities {
//     let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
//     crate::GenesisConfig::<Test>{
//         _phantom: Default::default(),
//         price_requests: vec![
//             (toVec("btc_price"), toVec("/api/getPartyPrice/btcusdt"), 1u32, 4u32),
//             (toVec("eth_price"), toVec("/api/getPartyPrice/ethusdt"), 1u32, 4u32),
//             (toVec("dot_price"), toVec("/api/getPartyPrice/dotusdt"), 1u32, 4u32),
//             (toVec("xrp_price"), toVec("/api/getPartyPrice/xrpusdt"), 1u32, 4u32),
//         ]
//     }.assimilate_storage(&mut t).unwrap();
//     t.into()
// }



pub fn new_test_ext() -> sp_io::TestExternalities {
    // let mut t = sp_io::TestExternalities::default();
    let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

    crate::GenesisConfig::<Test>{
        _phantom: Default::default(),
        request_base: "http://127.0.0.1:5566".as_bytes().to_vec(),
        price_allowable_offset: 10u8,
        price_pool_depth: 3u32,
        price_requests: vec![
            (toVec("btc_price"), toVec("btcusdt"), 2u32, 4u32, 1u8),
            (toVec("eth_price"), toVec("ethusdt"), 2u32, 4u32, 2u8),
            (toVec("dot_price"), toVec("dotusdt"), 2u32, 4u32, 3u8),
            (toVec("xrp_price"), toVec("xrpusdt"), 2u32, 4u32, 4u8),
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

// {"code":0,"message":"OK","data":{"btcusdt":{"price":50261.372,"timestamp":1629699168},"ethusdt":{"price":3107.71,"timestamp":1630055777},"dotusdt":{"price":35.9921,"timestamp":1631497660},"xrpusdt":{"price":1.09272,"timestamp":1631497987}}}
fn get_are_json_of_bulk() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"btcusdt\":{\"price\":50261.372,\"timestamp\":1629699168},\"ethusdt\":{\"price\":3107.71,\"timestamp\":1630055777},\"dotusdt\":{\"price\":35.9921,\"timestamp\":1631497660},\"xrpusdt\":{\"price\":1.09272,\"timestamp\":1631497987}}}"
}

// {"code":0,"message":"OK","data":{"btcusdt":{"price":50261.372,"timestamp":1629699168},"ethusdt":{"price":3107.71,"timestamp":1630055777},"dotusdt":{"price":35.9921,"timestamp":1631497660},"xrpusdt":{"price":1.09272,"timestamp":1631497987},"xxxusdt":{"price":1.09272,"timestamp":1631497987}}}
fn get_are_json_of_bulk_of_xxxusdt_is_0() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"btcusdt\":{\"price\":50261.372,\"timestamp\":1629699168},\"ethusdt\":{\"price\":3107.71,\"timestamp\":1630055777},\"dotusdt\":{\"price\":35.9921,\"timestamp\":1631497660},\"xrpusdt\":{\"price\":1.09272,\"timestamp\":1631497987},\"xxxusdt\":{\"price\":0,\"timestamp\":1631497987}}}"
}
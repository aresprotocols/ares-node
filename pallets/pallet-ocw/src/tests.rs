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
use crate as example_offchain_worker;
use std::sync::Arc;
use codec::Decode;
use frame_support::{assert_ok, parameter_types, ConsensusEngineId};
use sp_core::{
    H256,
    offchain::{OffchainWorkerExt, TransactionPoolExt, testing},
    sr25519::Signature,
};

use sp_keystore::{
    {KeystoreExt, SyncCryptoStore},
    testing::KeyStore,
};
use sp_runtime::{
    RuntimeAppPublic,
    testing::{Header, TestXt},
    traits::{
        BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
        IdentifyAccount, Verify,
    },
};

use sp_core::sr25519::Public as Public;

use frame_support::traits::{FindAuthor, VerifySeal};
use pallet_authorship::SealVerify;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// For testing the module, we construct a mock runtime.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Example: example_offchain_worker::{Pallet, Call, Storage, Event<T>, ValidateUnsigned},
		Authorship: pallet_authorship::{Pallet, Call, Storage, Inherent},
	}
);


// ------------- pallet_authorship BEGIN

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
	// pub const UncleGenerations: u64 = 5; on base test
}

impl pallet_authorship::Config for Test {
    type FindAuthor = AuthorGiven;
    type UncleGenerations = UncleGenerations;
    type FilterUncle = SealVerify<VerifyBlock>;
    type EventHandler = ();
}

// ---------- pallet_authorship END

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
	pub const GracePeriod: u64 = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl Config for Test {
    type Event = Event;
    type AuthorityId = crypto::TestAuthId;
    type Call = Call;
    type GracePeriod = GracePeriod;
    type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
}

// #[test]
// fn get_single_account() {
//     const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
//     let (offchain, offchain_state) = testing::TestOffchainExt::new();
//     let (pool, pool_state) = testing::TestTransactionPoolExt::new();
//     let keystore = KeyStore::new();
//     SyncCryptoStore::sr25519_generate_new(
//         &keystore,
//         crate::crypto::Public::ID,
//         Some(&format!("{}/hunter1", PHRASE)),
//     ).unwrap();
//
//     let mut t = sp_io::TestExternalities::default();
//     t.register_extension(OffchainWorkerExt::new(offchain));
//     t.register_extension(TransactionPoolExt::new(pool));
//     t.register_extension(KeystoreExt(Arc::new(keystore)));
//     // price_oracle_response(&mut offchain_state.write());
//
//     t.execute_with(|| {
//         // when
//         Example::get_single_account();
//         assert!(true);
//         // then
//         // let tx = pool_state.write().transactions.pop().unwrap();
//         // assert!(pool_state.read().transactions.is_empty());
//         // let tx = Extrinsic::decode(&mut &*tx).unwrap();
//         // assert_eq!(tx.signature.unwrap().0, 0);
//         // assert_eq!(tx.call, Call::Example(crate::Call::submit_price(15523)));
//
//         // when
//
//     });
// }


#[test]
fn get_single_account() {
    const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    SyncCryptoStore::sr25519_generate_new(
        &keystore,
        crate::crypto::Public::ID,
        Some(&format!("{}/hunter1", PHRASE)),
    ).unwrap();

    let public_key = SyncCryptoStore::sr25519_public_keys(&keystore, crate::crypto::Public::ID)
        .get(0)
        .unwrap()
        .clone();

    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    price_oracle_response(&mut offchain_state.write());

    let price_payload = PricePayload {
        block_number: 1,
        price: 15523,
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    // let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
    t.execute_with(|| {

        // Example::get_single_account();

        // when
        Example::fetch_price_and_send_unsigned_for_all_accounts(1).unwrap();
        // then
        // let tx = pool_state.write().transactions.pop().unwrap();
        // let tx = Extrinsic::decode(&mut &*tx).unwrap();
        // assert_eq!(tx.signature, None);
        // if let Call::Example(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
        //     assert_eq!(body, price_payload);
        //
        //     let signature_valid = <PricePayload<
        //         <Test as SigningTypes>::Public,
        //         <Test as frame_system::Config>::BlockNumber
        //     > as SignedPayload<Test>>::verify::<crypto::TestAuthId>(&price_payload, signature);
        //
        //     assert!(signature_valid);
        // }
    });
}

#[test]
fn it_aggregates_the_price() {
    sp_io::TestExternalities::default().execute_with(|| {
        assert_eq!(Example::average_price(), None);
        // TODO::提交一个具名价格
        assert_ok!(Example::submit_price(Origin::signed(Default::default()), 27));
        assert_eq!(Example::average_price(), Some(27));
        assert_ok!(Example::submit_price(Origin::signed(Default::default()), 43));
        assert_eq!(Example::average_price(), Some(35));
    });
}

// TODO:: 测试 http json 的结果解析。
#[test]
fn should_make_http_call_and_parse_result() {
    let (offchain, state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    // TODO::设置测试用的回复信息
    price_oracle_response(&mut state.write());

    t.execute_with(|| {
        // when
        let price = Example::fetch_price().unwrap();
        // then
        assert_eq!(price, 15523);
    });
}

#[test]
fn knows_how_to_mock_several_http_calls() {
    let (offchain, state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    {
        let mut state = state.write();
        state.expect_request(testing::PendingRequest {
            method: "GET".into(),
            uri: "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD".into(),
            response: Some(br#"{"USD": 1}"#.to_vec()),
            sent: true,
            ..Default::default()
        });

        state.expect_request(testing::PendingRequest {
            method: "GET".into(),
            uri: "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD".into(),
            response: Some(br#"{"USD": 2}"#.to_vec()),
            sent: true,
            ..Default::default()
        });

        state.expect_request(testing::PendingRequest {
            method: "GET".into(),
            uri: "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD".into(),
            response: Some(br#"{"USD": 3}"#.to_vec()),
            sent: true,
            ..Default::default()
        });
    }


    t.execute_with(|| {
        let price1 = Example::fetch_price().unwrap();
        let price2 = Example::fetch_price().unwrap();
        let price3 = Example::fetch_price().unwrap();

        assert_eq!(price1, 100);
        assert_eq!(price2, 200);
        assert_eq!(price3, 300);
    })
}


// TODO::提交一个签名的交易
#[test]
fn should_submit_signed_transaction_on_chain() {
    const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();
    // TODO::创建钥匙对
    let keystore = KeyStore::new();
    SyncCryptoStore::sr25519_generate_new(
        &keystore,
        crate::crypto::Public::ID,
        Some(&format!("{}/hunter1", PHRASE)),
    ).unwrap();


    let mut t = sp_io::TestExternalities::default();
    // TODO:: OffchainWorkerExt, TransactionPoolExt 都是在 sp_core::offchain 中定义的。
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    // TODO:: 注册了一个预言机的模拟价格请求。
    price_oracle_response(&mut offchain_state.write());

    t.execute_with(|| {
        // when
        Example::fetch_price_and_send_signed().unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature.unwrap().0, 0);
        assert_eq!(tx.call, Call::Example(crate::Call::submit_price(15523)));
    });
}

#[test]
fn should_submit_unsigned_transaction_on_chain_for_any_account() {
    const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    SyncCryptoStore::sr25519_generate_new(
        &keystore,
        crate::crypto::Public::ID,
        Some(&format!("{}/hunter1", PHRASE)),
    ).unwrap();

    let public_key = SyncCryptoStore::sr25519_public_keys(&keystore, crate::crypto::Public::ID)
        .get(0)
        .unwrap()
        .clone();

    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));
    price_oracle_response(&mut offchain_state.write());

    let price_payload = PricePayload {
        block_number: 1,
        price: 15523,
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    // let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
    t.execute_with(|| {
        // TODO:: when , block number is 1
        Example::fetch_price_and_send_unsigned_for_any_account(1).unwrap();
        // TODO:: then, get transaction list.
        let tx = pool_state.write().transactions.pop().unwrap();
        // TODO:: 解编码用于判断断言。
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        // TODO:: 签名不存在
        assert_eq!(tx.signature, None);

        if let Call::Example(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
            assert_eq!(body, price_payload);
            let signature_valid = <PricePayload<
                <Test as SigningTypes>::Public,
                <Test as frame_system::Config>::BlockNumber
            > as SignedPayload<Test>>::verify::<crypto::TestAuthId>(&price_payload, signature);


            assert!(signature_valid);
        }
    });
}

#[test]
fn should_submit_unsigned_transaction_on_chain_for_all_accounts() {
    const PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    SyncCryptoStore::sr25519_generate_new(
        &keystore,
        crate::crypto::Public::ID,
        Some(&format!("{}/hunter1", PHRASE)),
    ).unwrap();

    let public_key = SyncCryptoStore::sr25519_public_keys(&keystore, crate::crypto::Public::ID)
        .get(0)
        .unwrap()
        .clone();

    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    price_oracle_response(&mut offchain_state.write());

    let price_payload = PricePayload {
        block_number: 1,
        price: 15523,
        public: <Test as SigningTypes>::Public::from(public_key),
    };

    // let signature = price_payload.sign::<crypto::TestAuthId>().unwrap();
    t.execute_with(|| {
        // when
        Example::fetch_price_and_send_unsigned_for_all_accounts(1).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        if let Call::Example(crate::Call::submit_price_unsigned_with_signed_payload(body, signature)) = tx.call {
            assert_eq!(body, price_payload);

            let signature_valid = <PricePayload<
                <Test as SigningTypes>::Public,
                <Test as frame_system::Config>::BlockNumber
            > as SignedPayload<Test>>::verify::<crypto::TestAuthId>(&price_payload, signature);

            assert!(signature_valid);
        }
    });
}

#[test]
fn should_submit_raw_unsigned_transaction_on_chain() {
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    price_oracle_response(&mut offchain_state.write());

    t.execute_with(|| {
        // when
        Example::fetch_price_and_send_raw_unsigned(1).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        assert_eq!(tx.call, Call::Example(crate::Call::submit_price_unsigned(1, 15523)));
    });
}

fn price_oracle_response(state: &mut testing::OffchainState) {
    state.expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD".into(),
        response: Some(br#"{"USD": 155.23}"#.to_vec()),
        sent: true,
        ..Default::default()
    });
}

#[test]
fn parse_price_works() {
    // TODO::创建一个断言的数据类型。
    let test_data = vec![
        ("{\"USD\":6536.92}", Some(653692)),
        ("{\"USD\":65.92}", Some(6592)),
        ("{\"USD\":6536.924565}", Some(653692)), // TODO::注意小数点后面会被忽略
        ("{\"USD\":6536}", Some(653600)),
        ("{\"USD2\":6536}", None), // TODO:: Usd 2 是错的所以没有通过
        ("{\"USD\":\"6432\"}", None), // TODO:: Json 后面不是数值类型
    ];

    for (json, expected) in test_data {
        let second = Example::parse_price(json);
        assert_eq!(expected, second);
    }
}

// TODO:: Ares to do.

#[test]
fn parse_price_ares_works() {
    let price_str = get_are_json_of_btc();
    let test_data = vec![
        (price_str, Some(5026137)),
    ];

    for (json, expected) in test_data {
        let second = Example::parse_price_of_ares(json);
        assert_eq!(expected, second);
    }
}

#[test]
fn should_make_http_call_and_parse_ares_result() {
    let (offchain, state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
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
        let price = Example::fetch_price_of_ares().unwrap();
        assert_eq!(price, 5026137);
    });
}

#[test]
fn should_submit_raw_unsigned_ares_owc_transaction_on_chain() {
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, pool_state) = testing::TestTransactionPoolExt::new();

    let keystore = KeyStore::new();

    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    let json_response = get_are_json_of_btc().as_bytes().to_vec();

    offchain_state.write().expect_request(testing::PendingRequest {
        method: "GET".into(),
        uri: "http://141.164.58.241:5566/api/getPartyPrice/btcusdt".into(),
        response: Some(json_response),
        sent: true,
        ..Default::default()
    });

    t.execute_with(|| {
        // when
        Example::fetch_ares_price_and_send_raw_unsigned(1).unwrap();
        // then
        let tx = pool_state.write().transactions.pop().unwrap();
        assert!(pool_state.read().transactions.is_empty());
        let tx = Extrinsic::decode(&mut &*tx).unwrap();
        assert_eq!(tx.signature, None);
        assert_eq!(tx.call, Call::Example(crate::Call::submit_price_unsigned(1, 5026137)));
    });
}

// fn get_are_json_of_btc(price : &str) -> &str{
// 	let btc_str = format!("{{\"code\":0,\"message\":\"OK\",\"data\":{{\"price\":{},\"timestamp\":1629699168,\"infos\":[{{\"price\":50244.79,\"weight\":1,\"exchangeName\":\"binance\"}},{{\"price\":50243.16,\"weight\":1,\"exchangeName\":\"cryptocompare\"}},{{\"price\":50274,\"weight\":1,\"exchangeName\":\"bitfinex\"}},{{\"price\":50301.59,\"weight\":1,\"exchangeName\":\"bitstamp\"}},{{\"price\":50243.32,\"weight\":1,\"exchangeName\":\"huobi\"}}]}}}}",price).as_str();
// 	btc_str.clone()
// }

fn get_are_json_of_btc() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":50261.372,\"timestamp\":1629699168,\"infos\":[{\"price\":50244.79,\"weight\":1,\"exchangeName\":\"binance\"},{\"price\":50243.16,\"weight\":1,\"exchangeName\":\"cryptocompare\"},{\"price\":50274,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":50301.59,\"weight\":1,\"exchangeName\":\"bitstamp\"},{\"price\":50243.32,\"weight\":1,\"exchangeName\":\"huobi\"}]}}"
}

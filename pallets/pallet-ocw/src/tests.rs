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
use frame_support::{parameter_types, ConsensusEngineId};
use sp_core::{
    H256,
    offchain::{OffchainWorkerExt, TransactionPoolExt, testing},
    sr25519::Signature,
};

use sp_keystore::{
    {KeystoreExt},
    testing::KeyStore,
};
use sp_runtime::{
    testing::{Header, TestXt},
    traits::{
        BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
        IdentifyAccount, Verify,
    },
};

use sp_core::sr25519::Public as Public;

use frame_support::traits::{FindAuthor, VerifySeal};
use pallet_authorship::SealVerify;
// use frame_system::Origin;

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
    type AuthorityAres = sr25519::AuthorityId;
    type Call = Call;
    type GracePeriod = GracePeriod;
    type UnsignedInterval = UnsignedInterval;
    type UnsignedPriority = UnsignedPriority;
}

// TODO:: Ares to do.

#[test]
fn addprice_of_ares () {
    let (offchain, _state) = testing::TestOffchainExt::new();
    let mut t = sp_io::TestExternalities::default();
    t.register_extension(OffchainWorkerExt::new(offchain));

    // price_oracle_response(&mut state.write());

    t.execute_with(|| {
        let price_key = PriceKey::PRICE_KEY_IS_BTC;
        // when
        Example::add_price(Default::default(), 8888, price_key.clone());
        Example::add_price(Default::default(), 9999, price_key.clone());

        let btc_price_list = Example::ares_prices("btc_price".as_bytes().to_vec().clone());
        assert_eq!(vec![8888, 9999], btc_price_list);


        let price_key = PriceKey::PRICE_KEY_IS_ETH;
        // when
        Example::add_price(Default::default(), 7777, price_key.clone());
        let btc_price_list = Example::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(vec![7777], btc_price_list);

        Example::add_price(Default::default(), 6666, price_key.clone());
        let btc_price_list = Example::ares_prices("eth_price".as_bytes().to_vec().clone());
        assert_eq!(vec![7777, 6666], btc_price_list);

    });
}

#[test]
fn parse_price_ares_works() {
    let test_data = vec![
        (get_are_json_of_btc(), Some(5026137)),
        (get_are_json_of_eth(), Some(310771)),
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
        let price = Example::fetch_price_of_ares(PriceKey::PRICE_KEY_IS_BTC).unwrap();
        assert_eq!(price, 5026137);
    });
}

// // TODO:: The test cannot be executed, but it is very much needed.
// #[test]
// fn should_submit_raw_unsigned_ares_owc_transaction_on_chain() {
//     let (offchain, offchain_state) = testing::TestOffchainExt::new();
//     let (pool, pool_state) = testing::TestTransactionPoolExt::new();
//
//     let keystore = KeyStore::new();
//
//     let mut t = sp_io::TestExternalities::default();
//     t.register_extension(OffchainWorkerExt::new(offchain));
//     t.register_extension(TransactionPoolExt::new(pool));
//     t.register_extension(KeystoreExt(Arc::new(keystore)));
//
//     let json_response = get_are_json_of_btc().as_bytes().to_vec();
//
//     offchain_state.write().expect_request(testing::PendingRequest {
//         method: "GET".into(),
//         uri: "http://141.164.58.241:5566/api/getPartyPrice/btcusdt".into(),
//         response: Some(json_response),
//         sent: true,
//         ..Default::default()
//     });
//
//     t.execute_with(|| {
//         // when
//         Example::fetch_ares_price_and_send_raw_unsigned(1).unwrap();
//         // then
//         let tx = pool_state.write().transactions.pop().unwrap();
//         assert!(pool_state.read().transactions.is_empty());
//         let tx = Extrinsic::decode(&mut &*tx).unwrap();
//         assert_eq!(tx.signature, None);
//         assert_eq!(tx.call, Call::Example(crate::Call::submit_price_unsigned(1, vec![(PriceKey::PRICE_KEY_IS_BTC, 5026137)] )));
//     });
// }

fn get_are_json_of_btc() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":50261.372,\"timestamp\":1629699168,\"infos\":[{\"price\":50244.79,\"weight\":1,\"exchangeName\":\"binance\"},{\"price\":50243.16,\"weight\":1,\"exchangeName\":\"cryptocompare\"},{\"price\":50274,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":50301.59,\"weight\":1,\"exchangeName\":\"bitstamp\"},{\"price\":50243.32,\"weight\":1,\"exchangeName\":\"huobi\"}]}}"
}

fn get_are_json_of_eth() -> &'static str {
    "{\"code\":0,\"message\":\"OK\",\"data\":{\"price\":3107.71,\"timestamp\":1630055777,\"infos\":[{\"price\":3107,\"weight\":1,\"exchangeName\":\"huobi\"},{\"price\":3106.56,\"weight\":1,\"exchangeName\":\"cryptocompare\"},{\"price\":3106.68,\"weight\":1,\"exchangeName\":\"ok\"},{\"price\":3107,\"weight\":1,\"exchangeName\":\"bitfinex\"},{\"price\":3111.31,\"weight\":1,\"exchangeName\":\"bitstamp\"}]}}"
}
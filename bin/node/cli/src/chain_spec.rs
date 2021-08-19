// This file is part of Substrate.

// Copyright (C) 2018-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate chain configurations.

use sc_chain_spec::ChainSpecExtension;
use sp_core::{Pair, Public, crypto::UncheckedInto, sr25519};
use serde::{Serialize, Deserialize};
use node_runtime::{
	AuthorityDiscoveryConfig, BabeConfig, BalancesConfig, ContractsConfig, CouncilConfig,
	DemocracyConfig,GrandpaConfig, ImOnlineConfig, SessionConfig, SessionKeys, StakerStatus,
	StakingConfig, ElectionsConfig, IndicesConfig, SocietyConfig, SudoConfig, SystemConfig,
	TechnicalCommitteeConfig, wasm_binary_unwrap,
};
use node_runtime::Block;
use node_runtime::constants::currency::*;
use sc_service::ChainType;
use hex_literal::hex;
use sc_telemetry::TelemetryEndpoints;
use grandpa_primitives::{AuthorityId as GrandpaId};
use sp_consensus_babe::{AuthorityId as BabeId};
use pallet_im_online::sr25519::{AuthorityId as ImOnlineId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_runtime::{Perbill, traits::{Verify, IdentifyAccount}};

pub use node_primitives::{AccountId, Balance, Signature};
pub use node_runtime::GenesisConfig;

type AccountPublic = <Signature as Verify>::Signer;

const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
	/// Block numbers with known hashes.
	pub fork_blocks: sc_client_api::ForkBlocks<Block>,
	/// Known bad block hashes.
	pub bad_blocks: sc_client_api::BadBlocks<Block>,
}

/// Specialized `ChainSpec`.
pub type ChainSpec = sc_service::GenericChainSpec<
	GenesisConfig,
	Extensions,
>;
/// Flaming Fir testnet generator
pub fn flaming_fir_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/flaming-fir.json")[..])
}

fn session_keys(
	grandpa: GrandpaId,
	babe: BabeId,
	im_online: ImOnlineId,
	authority_discovery: AuthorityDiscoveryId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online, authority_discovery }
}

fn staging_testnet_config_genesis() -> GenesisConfig {
	// stash, controller, session-key
	// generated with secret:
	// for i in 1 2 3 4 ; do for j in stash controller; do subkey inspect "$secret"/fir/$j/$i; done; done
	// and
	// for i in 1 2 3 4 ; do for j in session; do subkey --ed25519 inspect "$secret"//fir//$j//$i; done; done

	let initial_authorities: Vec<(AccountId, AccountId, GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId)> = vec![(
		// AccountId：5Ebj7Z9DUSUjHUaqQGsH15iFe83GWbznJgWKbyLCWPoVMbWK
		hex!["70214e02fb2ec155a4c7bb8c122864b3b03f58c4ac59e8d83af7dc29851df657"].into(),
		// AccountId：5FvqX8XdznMZajt4oiGqmm87p1tW48yksTU6mPwtDFdcviQh
		hex!["aaf0c45982a423036601dcacc67854b38b854690d8e15bf1543e9a00e660e019"].into(),
		// GrandpaId：5DQevdMyhfto9mME5BQoWTFySM21KsViJeTS21hSLjkqMMv7
		hex!["3b7345bd36fb53c50be544a7c2847b9673984fa587af0c27108d3d464183e94f"].unchecked_into(),
		// BabeId：5CkjXVnejasckXZPqNZRnfrUx4kSLrZhbzJJcU4ZVJ63VuoL
		hex!["1e876fa1b4bbb82785ea5670b7ce0976beaf7536b6a0cc05deba7a54ab709421"].unchecked_into(),
		// ImOnlineId: 5FS4nFmakmC7xydzUcsU14H51E2HEpmrdAym2hfEDihY9Vyp
		hex!["94ff4a3dcd40926a375e9ebd640972598f7cf372e745fc5727a8020864bcb850"].unchecked_into(),
		// AuthorityDiscoveryId
		hex!["1e876fa1b4bbb82785ea5670b7ce0976beaf7536b6a0cc05deba7a54ab709421"].unchecked_into(),
	),(
		// AccountId：5GbAZyAiXR9xPWjRRV9txrCCh9CpxUBmGm5grXAGdReCzShY
		hex!["c82c3780d981812be804345618d27228680f61bb06a22689dcacf32b9be8815a"].into(),
		// AccountId：5EhdNat32kdbSSfgwwyHMfMX27sFeDdmgSh665LdhisxugB2
		hex!["74a173a22757ddc9790ed388953a1ed8a5933a421858533411b36ebd41d74165"].into(),
		// GrandpaId：5FiMnGQ7soNQe6kCh8LhoD6Za4eEMLbxKXDB5MDCsYixcpHG
		hex!["a16c71b78c13cbd73e09cc348be1e8521ec2ce4c2615d4f2cf0e8148ba454a05"].unchecked_into(),
		// BabeId：5GpWMMCTjhZcZPEMgei3RXQdBKMo4L8dPoM2BeXrNcoPvQGG
		hex!["d25900272b16897ec18a04b7d7d704954e6bdc35ae5a09305aa2e0cc2bf10e5c"].unchecked_into(),
		// ImOnlineId:5EZVtoYNs91WyfPUZCDbH8zWhA3eMz3x4qzr4mUETF8ijv7p
		hex!["6e6e4fd9c9ec79c902245ae1571d765ab24ff746620d138c2f2a0e3120634317"].unchecked_into(),
		// AuthorityDiscoveryId
		hex!["d25900272b16897ec18a04b7d7d704954e6bdc35ae5a09305aa2e0cc2bf10e5c"].unchecked_into(),
	),(
		// AccountId：5Fy7d56q8apQciKoex9EfBrGQGguQGaFHJYR9UGkYMn56PuX
		hex!["acad76a1f273ab3b8e453d630d347668f1cfa9b01605800dab7126a494c04c7c"].into(),
		// AccountId：5FeJxhZhmfED6PqRge9SpMzsJi33JxnZWoBNeg6aEPx3jC2d
		hex!["9e55f821f7b3484f15942af308001c32f113f31444f420a77422702907510669"].into(),
		// GrandpaId：5D5ae1KVDr3U8X5fFwKzGkzNJKW4dmC2iSAHQ9ZTfMer5EbM
		hex!["2ce72e098beb0bc8ed6c812099bed8c7c60ae8208c94abf4212d7fdeaf11bab3"].unchecked_into(),
		// BabeId：5G9Qktxa1ee2RCWeHZY1itHZaTMagCHeNVWHoJhvknJBbuQS
		hex!["b4879945ce4ef0b387857026c2b6fc8b15dec3386ad13b7bf7d978e484080a18"].unchecked_into(),
		// ImOnlineId:5GHTVeYT1AYQyjLdUaAxGUCJR3SUkFEVZ9PdwPuXuAVaWrKq
		hex!["baaac69d2f30aeafcddd0fc43d23129aed7dde874cabb98efc3ab5b18fffa277"].unchecked_into(),
		// AuthorityDiscoveryId
		hex!["b4879945ce4ef0b387857026c2b6fc8b15dec3386ad13b7bf7d978e484080a18"].unchecked_into(),
	),(
		// AccountId：5DkaySbFDzQ8RwNa6JnMdEFFdB8LpMuGCQGYfmUGZbZuPGW6
		hex!["4aa6e0eeed2e3d1f35a8eb1cd650451327ad378fb8975dbf5747016ff3be2460"].into(),
		// AccountId：5E4ip35pxFHj3JSYhaLcDZNnFYdqserEg9imnwL5ssM1WzHy
		hex!["587bae319ecaee13ce2dbdedfc6d66eb189e5af427666b21b4d4a08c7af0671c"].into(),
		// GrandpaId：5G66d3SAkfaBfDz7h5vRTMpsHMiNirNFkt1HrmQcCDJWehDk
		hex!["b200d0328d26f7cbb67223c179ab14a2152d7afb6689f07b618fda33695d5fd4"].unchecked_into(),
		// BabeId：5CUrhxK8xSwiyUBHtBdEGCuqhNe9At646hdpQBbrdG1bRb4B
		hex!["126bae3dea6a6a6e346bc0dc2beb4e1c9e54aaf1c0732bf67ff03d772f6a6208"].unchecked_into(),
		// ImOnlineId:5GEMxvuB7Kvs7JXUMiP8u7oLK8uUFqAfb25wn7nj1dNjm1WN
		hex!["b84e6cddf2b6e1ff5c76b8a71361e3f7a52c76605dbd2cfc069cec8975e12e1b"].unchecked_into(),
		// AuthorityDiscoveryId
		hex!["126bae3dea6a6a6e346bc0dc2beb4e1c9e54aaf1c0732bf67ff03d772f6a6208"].unchecked_into(),
	)];

	// generated with secret: subkey inspect "$secret"/fir
	let root_key: AccountId = hex![
		// 5Ff3iXP75ruzroPWRP2FYBHWnmGGBSb63857BgnzCoXNxfPo
		"9ee5e5bdc0ec239eb164f865ecc345ce4c88e76ee002e0f7e318097347471809"
	].into();

	let endowed_accounts: Vec<AccountId> = vec![root_key.clone()];

	testnet_genesis(
		initial_authorities,
		root_key,
		Some(endowed_accounts),
		false,
	)
}

/// Staging testnet config.
pub fn staging_testnet_config() -> ChainSpec {
	let boot_nodes = vec![];
	ChainSpec::from_genesis(
		"Staging Testnet",
		"staging_testnet",
		ChainType::Live,
		staging_testnet_config_genesis,
		boot_nodes,
		Some(TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
			.expect("Staging telemetry url is valid; qed")),
		None,
		None,
		Default::default(),
	)
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate stash, controller and session key from seed
pub fn authority_keys_from_seed(seed: &str) -> (
	AccountId,
	AccountId,
	GrandpaId,
	BabeId,
	ImOnlineId,
	AuthorityDiscoveryId,
) {
	(
		get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
		get_account_id_from_seed::<sr25519::Public>(seed),
		get_from_seed::<GrandpaId>(seed),
		get_from_seed::<BabeId>(seed),
		get_from_seed::<ImOnlineId>(seed),
		get_from_seed::<AuthorityDiscoveryId>(seed),
	)
}

/// Helper function to create GenesisConfig for testing
pub fn testnet_genesis(
	initial_authorities: Vec<(
		AccountId,
		AccountId,
		GrandpaId,
		BabeId,
		ImOnlineId,
		AuthorityDiscoveryId,
	)>,
	root_key: AccountId,
	endowed_accounts: Option<Vec<AccountId>>,
	enable_println: bool,
) -> GenesisConfig {
	let mut endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(|| {
		vec![
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			get_account_id_from_seed::<sr25519::Public>("Bob"),
			get_account_id_from_seed::<sr25519::Public>("Charlie"),
			get_account_id_from_seed::<sr25519::Public>("Dave"),
			get_account_id_from_seed::<sr25519::Public>("Eve"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie"),
			get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
			get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
			get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
			get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
			get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
		]
	});
	initial_authorities.iter().for_each(|x|
		if !endowed_accounts.contains(&x.0) {
			endowed_accounts.push(x.0.clone())
		}
	);

	let num_endowed_accounts = endowed_accounts.len();

	const ENDOWMENT: Balance = 10_000_000 * DOLLARS;
	const STASH: Balance = ENDOWMENT / 1000;

	GenesisConfig {
		frame_system: Some(SystemConfig {
			code: wasm_binary_unwrap().to_vec(),
			changes_trie_config: Default::default(),
		}),
		pallet_balances: Some(BalancesConfig {
			balances: endowed_accounts.iter().cloned()
				.map(|x| (x, ENDOWMENT))
				.collect()
		}),
		pallet_indices: Some(IndicesConfig {
			indices: vec![],
		}),
		pallet_session: Some(SessionConfig {
			keys: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.0.clone(), session_keys(
					x.2.clone(),
					x.3.clone(),
					x.4.clone(),
					x.5.clone(),
				))
			}).collect::<Vec<_>>(),
		}),
		pallet_staking: Some(StakingConfig {
			validator_count: initial_authorities.len() as u32 * 2,
			minimum_validator_count: initial_authorities.len() as u32,
			stakers: initial_authorities.iter().map(|x| {
				(x.0.clone(), x.1.clone(), STASH, StakerStatus::Validator)
			}).collect(),
			invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
			slash_reward_fraction: Perbill::from_percent(10),
			.. Default::default()
		}),
		pallet_democracy: Some(DemocracyConfig::default()),
		pallet_elections_phragmen: Some(ElectionsConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.map(|member| (member, STASH))
						.collect(),
		}),
		pallet_collective_Instance1: Some(CouncilConfig::default()),
		pallet_collective_Instance2: Some(TechnicalCommitteeConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.collect(),
			phantom: Default::default(),
		}),
		pallet_contracts: Some(ContractsConfig {
			current_schedule: pallet_contracts::Schedule {
				enable_println, // this should only be enabled on development chains
				..Default::default()
			},
		}),
		pallet_sudo: Some(SudoConfig {
			key: root_key,
		}),
		pallet_babe: Some(BabeConfig {
			authorities: vec![],
		}),
		pallet_im_online: Some(ImOnlineConfig {
			keys: vec![],
		}),
		pallet_authority_discovery: Some(AuthorityDiscoveryConfig {
			keys: vec![],
		}),
		pallet_grandpa: Some(GrandpaConfig {
			authorities: vec![],
		}),
		pallet_membership_Instance1: Some(Default::default()),
		pallet_treasury: Some(Default::default()),
		pallet_society: Some(SocietyConfig {
			members: endowed_accounts.iter()
						.take((num_endowed_accounts + 1) / 2)
						.cloned()
						.collect(),
			pot: 0,
			max_members: 999,
		}),
		pallet_vesting: Some(Default::default()),
	}
}

fn development_config_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
		],
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		None,
		true,
	)
}

/// Development config (single validator Alice)
pub fn development_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Development",
		"dev",
		ChainType::Development,
		development_config_genesis,
		vec![],
		None,
		None,
		None,
		Default::default(),
	)
}

fn local_testnet_genesis() -> GenesisConfig {
	testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
		],
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		None,
		false,
	)
}

/// Local testnet config (multivalidator Alice + Bob)
pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::from_genesis(
		"Local Testnet",
		"local_testnet",
		ChainType::Local,
		local_testnet_genesis,
		vec![],
		None,
		None,
		None,
		Default::default(),
	)
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::service::{new_full_base, new_light_base, NewFullBase};
	use sc_service_test;
	use sp_runtime::BuildStorage;

	fn local_testnet_genesis_instant_single() -> GenesisConfig {
		testnet_genesis(
			vec![
				authority_keys_from_seed("Alice"),
			],
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			None,
			false,
		)
	}

	/// Local testnet config (single validator - Alice)
	pub fn integration_test_config_with_single_authority() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			ChainType::Development,
			local_testnet_genesis_instant_single,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	/// Local testnet config (multivalidator Alice + Bob)
	pub fn integration_test_config_with_two_authorities() -> ChainSpec {
		ChainSpec::from_genesis(
			"Integration Test",
			"test",
			ChainType::Development,
			local_testnet_genesis,
			vec![],
			None,
			None,
			None,
			Default::default(),
		)
	}

	#[test]
	#[ignore]
	fn test_connectivity() {
		sc_service_test::connectivity(
			integration_test_config_with_two_authorities(),
			|config| {
				let NewFullBase { task_manager, client, network, transaction_pool, .. }
					= new_full_base(config,|_, _| ())?;
				Ok(sc_service_test::TestNetComponents::new(task_manager, client, network, transaction_pool))
			},
			|config| {
				let (keep_alive, _, _, client, network, transaction_pool) = new_light_base(config)?;
				Ok(sc_service_test::TestNetComponents::new(keep_alive, client, network, transaction_pool))
			}
		);
	}

	#[test]
	fn test_create_development_chain_spec() {
		development_config().build_storage().unwrap();
	}

	#[test]
	fn test_create_local_testnet_chain_spec() {
		local_testnet_config().build_storage().unwrap();
	}

	#[test]
	fn test_staging_test_net_chain_spec() {
		staging_testnet_config().build_storage().unwrap();
	}
}

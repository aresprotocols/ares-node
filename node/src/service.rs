//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use futures::prelude::*;
use futures::stream::Stream;
use runtime_gladios_node::{
	self, opaque::Block, part_ocw::LOCAL_STORAGE_PRICE_REQUEST_DOMAIN, RuntimeApi,
};
use sc_client_api::{Backend, ExecutorProvider, RemoteBackend};
// use ocw_sc_consensus_aura as sc_consensus_aura;
// use sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use sc_consensus_babe::{self, SlotProportion};
pub use sc_executor::NativeElseWasmExecutor;
use sc_finality_grandpa::SharedVoterState;
use sc_keystore::LocalKeystore;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, RpcHandlers};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_consensus::SlotData;
use sc_network::{Event, NetworkService};

// use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;

use std::{sync::Arc, time::Duration};
// use sp_runtime::sp_std;
use frame_support::pallet_prelude::Encode;
use frame_support::sp_std;
use log;
use seed_reader::*;
use sp_core::offchain::OffchainStorage;
use sp_offchain::STORAGE_PREFIX;
use std::io::Read;
use sp_api::BlockT;
use crate::node_rpc;
// use frame_support::{dispatch::DispatchResult, pallet_prelude::*};

// Our native executor instance.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
	type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		runtime_gladios_node::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		runtime_gladios_node::native_version()
	}
}

type FullClient =
sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
sc_finality_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;
type LightClient =
sc_service::TLightClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

// pub fn new_partial(
// 	config: &Configuration,
// ) -> Result<
// 	sc_service::PartialComponents<
// 		FullClient,
// 		FullBackend,
// 		FullSelectChain,
// 		sc_consensus::DefaultImportQueue<Block, FullClient>,
//
// 		sc_transaction_pool::FullPool<Block, FullClient>,
// 		(
// 			impl Fn(
// 				node_rpc::DenyUnsafe,
// 				sc_rpc::SubscriptionTaskExecutor,
// 			) -> Result<node_rpc::IoHandler, sc_service::Error>,
// 			(
// 				sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
// 				sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
// 				sc_consensus_babe::BabeLink<Block>,
// 			),
// 			sc_finality_grandpa::SharedVoterState,
// 			Option<Telemetry>,
// 		),
// 	>,
// 	ServiceError,
// > {
// 	if config.keystore_remote.is_some() {
// 		return Err(ServiceError::Other(format!("Remote Keystores are not supported.")));
// 	}
//
// 	let telemetry = config
// 		.telemetry_endpoints
// 		.clone()
// 		.filter(|x| !x.is_empty())
// 		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
// 			let worker = TelemetryWorker::new(16)?;
// 			let telemetry = worker.handle().new_telemetry(endpoints);
// 			Ok((worker, telemetry))
// 		})
// 		.transpose()?;
//
// 	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
// 		config.wasm_method,
// 		config.default_heap_pages,
// 		config.max_runtime_instances,
// 	);
//
// 	let (client, backend, keystore_container, task_manager) =
// 		sc_service::new_full_parts::<Block, RuntimeApi, _>(
// 			&config,
// 			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
// 			executor,
// 		)?;
// 	let client = Arc::new(client);
//
// 	let telemetry = telemetry.map(|(worker, telemetry)| {
// 		task_manager.spawn_handle().spawn("telemetry", worker.run());
// 		telemetry
// 	});
//
// 	let select_chain = sc_consensus::LongestChain::new(backend.clone());
//
// 	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
// 		config.transaction_pool.clone(),
// 		config.role.is_authority().into(),
// 		config.prometheus_registry(),
// 		task_manager.spawn_essential_handle(),
// 		client.clone(),
// 	);
//
// 	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
// 		client.clone(),
// 		&(client.clone() as Arc<_>),
// 		select_chain.clone(),
// 		telemetry.as_ref().map(|x| x.handle()),
// 	)?;
//
// 	let justification_import = grandpa_block_import.clone();
//
// 	let (block_import, babe_link) = sc_consensus_babe::block_import(
// 		sc_consensus_babe::Config::get_or_compute(&*client)?,
// 		grandpa_block_import,
// 		client.clone(),
// 	)?;
//
// 	// let slot_duration = sc_consensus_aura::slot_duration(&*client)?.slot_duration();
// 	let slot_duration = babe_link.config().slot_duration();
//
// 	// let import_queue =
// 	// 	sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _, _>(ImportQueueParams {
// 	// 		block_import: grandpa_block_import.clone(),
// 	// 		justification_import: Some(Box::new(grandpa_block_import.clone())),
// 	// 		client: client.clone(),
// 	// 		create_inherent_data_providers: move |_, ()| async move {
// 	// 			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
// 	//
// 	// 			let slot =
// 	// 				sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
// 	// 					*timestamp,
// 	// 					slot_duration,
// 	// 				);
// 	//
// 	// 			Ok((timestamp, slot))
// 	// 		},
// 	// 		spawner: &task_manager.spawn_essential_handle(),
// 	// 		can_author_with: sp_consensus::CanAuthorWithNativeVersion::new(
// 	// 			client.executor().clone(),
// 	// 		),
// 	// 		registry: config.prometheus_registry(),
// 	// 		check_for_equivocation: Default::default(),
// 	// 		telemetry: telemetry.as_ref().map(|x| x.handle()),
// 	// 	})?;
//
// 	let import_queue = sc_consensus_babe::import_queue(
// 		babe_link.clone(),
// 		block_import.clone(),
// 		Some(Box::new(justification_import)),
// 		client.clone(),
// 		select_chain.clone(),
// 		move |_, ()| async move {
// 			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
//
// 			let slot =
// 				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_duration(
// 					*timestamp,
// 					slot_duration,
// 				);
//
// 			let uncles =
// 				sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();
//
// 			Ok((timestamp, slot, uncles))
// 		},
// 		&task_manager.spawn_essential_handle(),
// 		config.prometheus_registry(),
// 		sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
// 		telemetry.as_ref().map(|x| x.handle()),
// 	)?;
//
// 	let import_setup = (block_import, grandpa_link, babe_link);
//
// 	let (rpc_extensions_builder, rpc_setup) = {
// 		let (_, grandpa_link, babe_link) = &import_setup;
//
// 		let justification_stream = grandpa_link.justification_stream();
// 		let shared_authority_set = grandpa_link.shared_authority_set().clone();
// 		let shared_voter_state = sc_finality_grandpa::SharedVoterState::empty();
// 		let rpc_setup = shared_voter_state.clone();
//
// 		let finality_proof_provider = sc_finality_grandpa::FinalityProofProvider::new_for_service(
// 			backend.clone(),
// 			Some(shared_authority_set.clone()),
// 		);
//
// 		let babe_config = babe_link.config().clone();
// 		let shared_epoch_changes = babe_link.epoch_changes().clone();
//
// 		let client = client.clone();
// 		let pool = transaction_pool.clone();
// 		let select_chain = select_chain.clone();
// 		let keystore = keystore_container.sync_keystore();
// 		let chain_spec = config.chain_spec.cloned_box();
//
// 		let rpc_extensions_builder = move |deny_unsafe, subscription_executor| {
// 			let deps = node_rpc::FullDeps {
// 				client: client.clone(),
// 				pool: pool.clone(),
// 				select_chain: select_chain.clone(),
// 				chain_spec: chain_spec.cloned_box(),
// 				deny_unsafe,
// 				babe: node_rpc::BabeDeps {
// 					babe_config: babe_config.clone(),
// 					shared_epoch_changes: shared_epoch_changes.clone(),
// 					keystore: keystore.clone(),
// 				},
// 				grandpa: node_rpc::GrandpaDeps {
// 					shared_voter_state: shared_voter_state.clone(),
// 					shared_authority_set: shared_authority_set.clone(),
// 					justification_stream: justification_stream.clone(),
// 					subscription_executor,
// 					finality_provider: finality_proof_provider.clone(),
// 				},
// 			};
//
// 			node_rpc::create_full(deps).map_err(Into::into)
// 		};
//
// 		(rpc_extensions_builder, rpc_setup)
// 	};
//
// 	// Ok(sc_service::PartialComponents {
// 	// 	client,
// 	// 	backend,
// 	// 	task_manager,
// 	// 	import_queue,
// 	// 	keystore_container,
// 	// 	select_chain,
// 	// 	transaction_pool,
// 	// 	other: (grandpa_block_import, grandpa_link, telemetry),
// 	// })
//
// 	Ok(sc_service::PartialComponents {
// 		client,
// 		backend,
// 		task_manager,
// 		keystore_container,
// 		select_chain,
// 		import_queue,
// 		transaction_pool,
// 		other: (rpc_extensions_builder, import_setup, rpc_setup, telemetry),
// 	})
// }


pub fn new_partial(
	config: &Configuration,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(
			impl Fn(
				node_rpc::DenyUnsafe,
				sc_rpc::SubscriptionTaskExecutor,
			) -> Result<node_rpc::IoHandler, sc_service::Error>,
			(
				sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
				sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
				sc_consensus_babe::BabeLink<Block>,
			),
			sc_finality_grandpa::SharedVoterState,
			Option<Telemetry>,
		),
	>,
	ServiceError,
> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			&config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;
	let justification_import = grandpa_block_import.clone();

	let (block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::Config::get_or_compute(&*client)?,
		grandpa_block_import,
		client.clone(),
	)?;

	let slot_duration = babe_link.config().slot_duration();
	let import_queue = sc_consensus_babe::import_queue(
		babe_link.clone(),
		block_import.clone(),
		Some(Box::new(justification_import)),
		client.clone(),
		select_chain.clone(),
		move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

			let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_duration(
					*timestamp,
					slot_duration,
				);

			let uncles =
				sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();

			Ok((timestamp, slot, uncles))
		},
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
		sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let import_setup = (block_import, grandpa_link, babe_link);

	let (rpc_extensions_builder, rpc_setup) = {
		let (_, grandpa_link, babe_link) = &import_setup;

		let justification_stream = grandpa_link.justification_stream();
		let shared_authority_set = grandpa_link.shared_authority_set().clone();
		let shared_voter_state = sc_finality_grandpa::SharedVoterState::empty();
		let rpc_setup = shared_voter_state.clone();

		let finality_proof_provider = sc_finality_grandpa::FinalityProofProvider::new_for_service(
			backend.clone(),
			Some(shared_authority_set.clone()),
		);

		let babe_config = babe_link.config().clone();
		let shared_epoch_changes = babe_link.epoch_changes().clone();

		let client = client.clone();
		let pool = transaction_pool.clone();
		let select_chain = select_chain.clone();
		let keystore = keystore_container.sync_keystore();
		let chain_spec = config.chain_spec.cloned_box();

		let rpc_extensions_builder = move |deny_unsafe, subscription_executor| {
			let deps = node_rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				select_chain: select_chain.clone(),
				chain_spec: chain_spec.cloned_box(),
				deny_unsafe,
				babe: node_rpc::BabeDeps {
					babe_config: babe_config.clone(),
					shared_epoch_changes: shared_epoch_changes.clone(),
					keystore: keystore.clone(),
				},
				grandpa: node_rpc::GrandpaDeps {
					shared_voter_state: shared_voter_state.clone(),
					shared_authority_set: shared_authority_set.clone(),
					justification_stream: justification_stream.clone(),
					subscription_executor,
					finality_provider: finality_proof_provider.clone(),
				},
			};

			node_rpc::create_full(deps).map_err(Into::into)
		};

		(rpc_extensions_builder, rpc_setup)
	};

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		keystore_container,
		select_chain,
		import_queue,
		transaction_pool,
		other: (rpc_extensions_builder, import_setup, rpc_setup, telemetry),
	})
}

fn remote_keystore(_url: &String) -> Result<Arc<LocalKeystore>, &'static str> {
	// FIXME: here would the concrete keystore be built,
	//        must return a concrete type (NOT `LocalKeystore`) that
	//        implements `CryptoStore` and `SyncCryptoStore`
	Err("Remote Keystore not supported.")
}

pub struct NewFullBase {
	pub task_manager: TaskManager,
	pub client: Arc<FullClient>,
	pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
	pub transaction_pool: Arc<sc_transaction_pool::FullPool<Block, FullClient>>,
}

/// Builds a new service for a full client.
pub fn new_full_base(
	mut config: Configuration,
	with_startup_data: impl FnOnce(
		&sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
		&sc_consensus_babe::BabeLink<Block>,
	),
	ares_params: Vec<(&str, Option<Vec<u8>>)>,
) -> Result<NewFullBase, ServiceError>  {
	// let sc_service::PartialComponents {
	// 	client,
	// 	backend,
	// 	mut task_manager,
	// 	import_queue,
	// 	mut keystore_container,
	// 	select_chain,
	// 	transaction_pool,
	// 	other: (block_import, grandpa_link, mut telemetry),
	// } = new_partial(&config)?;

	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (rpc_extensions_builder, import_setup, rpc_setup, mut telemetry),
	} = new_partial(&config)?;

	let shared_voter_state = rpc_setup;
	let auth_disc_publish_non_global_ips = config.network.allow_non_globals_in_dht;

	// --- Not babe
	// if let Some(url) = &config.keystore_remote {
	// 	match remote_keystore(url) {
	// 		Ok(k) => keystore_container.set_remote_keystore(k),
	// 		Err(e) => {
	// 			return Err(ServiceError::Other(format!(
	// 				"Error hooking up remote keystore for {}: {}",
	// 				url, e
	// 			)))
	// 		}
	// 	};
	// }
	// ---

	// config.network.extra_sets.push(sc_finality_grandpa::grandpa_peers_set_config());
	// let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
	// 	backend.clone(),
	// 	grandpa_link.shared_authority_set().clone(),
	// ));

	config.network.extra_sets.push(sc_finality_grandpa::grandpa_peers_set_config());
	let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		import_setup.1.shared_authority_set().clone(),
	));

	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: None,
			block_announce_validator_builder: None,
			warp_sync: Some(warp_sync),
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}

	// let role = config.role.clone();
	// let force_authoring = config.force_authoring;
	// let backoff_authoring_blocks: Option<()> = None;
	// let name = config.network.node_name.clone();
	// let enable_grandpa = !config.disable_grandpa;
	// let prometheus_registry = config.prometheus_registry().cloned();

	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks =
		Some(sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default());
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();


	// let rpc_extensions_builder = {
	// 	let client = client.clone();
	// 	let pool = transaction_pool.clone();
	//
	// 	Box::new(move |deny_unsafe, _| {
	// 		let deps =
	// 			node_rpc::FullDeps { client: client.clone(), pool: pool.clone(), deny_unsafe };
	//
	// 		Ok(node_rpc::create_full(deps))
	// 	})
	// };


	let backend_clone = backend.clone();
	// let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
	// 	network: network.clone(),
	// 	client: client.clone(),
	// 	keystore: keystore_container.sync_keystore(),
	// 	task_manager: &mut task_manager,
	// 	transaction_pool: transaction_pool.clone(),
	// 	rpc_extensions_builder,
	// 	on_demand: None,
	// 	remote_blockchain: None,
	// 	backend,
	// 	system_rpc_tx,
	// 	config,
	// 	telemetry: telemetry.as_mut(),
	// })?;

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		backend: backend.clone(),
		client: client.clone(),
		keystore: keystore_container.sync_keystore(),
		network: network.clone(),
		rpc_extensions_builder: Box::new(rpc_extensions_builder),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		on_demand: None,
		remote_blockchain: None,
		system_rpc_tx,
		telemetry: telemetry.as_mut(),
	})?;

	log::info!("setting ares_params: {:?}", ares_params);
	let result: Vec<(&str, bool)> = ares_params
		.iter()
		.map(|(order, x)| {
			match order {
				&"warehouse" => {
					match x {
						None => (*order, false),
						Some(exe_vecu8) => {
							let request_base_str = sp_std::str::from_utf8(exe_vecu8).unwrap();
							let store_request_u8 = request_base_str.encode();
							log::info!("setting request_domain: {:?}", request_base_str);
							if let Some(mut offchain_db) = backend_clone.offchain_storage() {
								log::debug!("after setting request_domain: {:?}", request_base_str);
								offchain_db.set(
									STORAGE_PREFIX,
									LOCAL_STORAGE_PRICE_REQUEST_DOMAIN,
									store_request_u8.as_slice(),
								);
							}
							(*order, true)
						}
					}
				}
				&"ares-keys-file" => {
					match x {
						None => (*order, false),
						Some(exe_vecu8) => {
							let key_file_path = sp_std::str::from_utf8(exe_vecu8).unwrap();
							let mut file = std::fs::File::open(key_file_path).unwrap();
							let mut contents = String::new();
							file.read_to_string(&mut contents).unwrap();
							let rawkey_list = extract_content(contents.as_str());
							let insert_key_list: Vec<(&str, &str, String)> = rawkey_list
								.iter()
								.map(|x| make_author_insert_key_params(*x))
								.collect();
							let rpc_list: Vec<Option<String>> = insert_key_list
								.iter()
								.map(|x| {
									make_rpc_request("author_insertKey", (x.0, x.1, x.2.as_str()))
								})
								.collect();
							rpc_list.iter().any(|x| {
								if let Some(rpc_str) = x {
									// send rpc request.
									_rpc_handlers
										.io_handler()
										.handle_request_sync(rpc_str, sc_rpc::Metadata::default());
								}
								false
							});

							(*order, true)
						}
					}
				}
				&_ => ("NONE", false),
			}
		})
		.collect();

	// ---------

	let (block_import, grandpa_link, babe_link) = import_setup;
	(with_startup_data)(&block_import, &babe_link);

	if let sc_service::config::Role::Authority { .. } = &role {
		let proposer = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let can_author_with =
			sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

		let client_clone = client.clone();
		let slot_duration = babe_link.config().slot_duration();
		let babe_config = sc_consensus_babe::BabeParams {
			keystore: keystore_container.sync_keystore(),
			client: client.clone(),
			select_chain,
			env: proposer,
			block_import,
			sync_oracle: network.clone(),
			justification_sync_link: network.clone(),
			create_inherent_data_providers: move |parent, ()| {
				let client_clone = client_clone.clone();
				async move {
					let uncles = sc_consensus_uncles::create_uncles_inherent_data_provider(
						&*client_clone,
						parent,
					)?;

					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_duration(
							*timestamp,
							slot_duration,
						);

					let storage_proof =
						sp_transaction_storage_proof::registration::new_data_provider(
							&*client_clone,
							&parent,
						)?;

					Ok((timestamp, slot, uncles, storage_proof))
				}
			},
			force_authoring,
			backoff_authoring_blocks,
			babe_link,
			can_author_with,
			block_proposal_slot_portion: SlotProportion::new(0.5),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		let babe = sc_consensus_babe::start_babe(babe_config)?;
		task_manager.spawn_essential_handle().spawn_blocking("babe-proposer", babe);
	}

	// if role.is_authority() {
	// 	let proposer_factory = sc_basic_authorship::ProposerFactory::new(
	// 		task_manager.spawn_handle(),
	// 		client.clone(),
	// 		transaction_pool,
	// 		prometheus_registry.as_ref(),
	// 		telemetry.as_ref().map(|x| x.handle()),
	// 	);
	//
	// 	let can_author_with =
	// 		sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());
	//
	// 	let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
	// 	let raw_slot_duration = slot_duration.slot_duration();
	//
	// 	let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _, _>(
	// 		StartAuraParams {
	// 			slot_duration,
	// 			client: client.clone(),
	// 			select_chain,
	// 			block_import,
	// 			proposer_factory,
	// 			create_inherent_data_providers: move |_, ()| async move {
	// 				let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
	//
	// 				let slot =
	// 					sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
	// 						*timestamp,
	// 						raw_slot_duration,
	// 					);
	//
	// 				Ok((timestamp, slot))
	// 			},
	// 			force_authoring,
	// 			backoff_authoring_blocks,
	// 			keystore: keystore_container.sync_keystore(),
	// 			can_author_with,
	// 			sync_oracle: network.clone(),
	// 			justification_sync_link: network.clone(),
	// 			block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
	// 			max_block_proposal_slot_portion: None,
	// 			telemetry: telemetry.as_ref().map(|x| x.handle()),
	// 		},
	// 	)?;
	//
	// 	// the AURA authoring task is considered essential, i.e. if it
	// 	// fails we take down the service with it.
	// 	task_manager.spawn_essential_handle().spawn_blocking("aura", aura);
	// }

	if role.is_authority() {
		let authority_discovery_role =
			sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore());
		let dht_event_stream =
			network.event_stream("authority-discovery").filter_map(|e| async move {
				match e {
					Event::Dht(e) => Some(e),
					_ => None,
				}
			});
		let (authority_discovery_worker, _service) =
			sc_authority_discovery::new_worker_and_service_with_config(
				sc_authority_discovery::WorkerConfig {
					publish_non_global_ips: auth_disc_publish_non_global_ips,
					..Default::default()
				},
				client.clone(),
				network.clone(),
				Box::pin(dht_event_stream),
				authority_discovery_role,
				prometheus_registry.clone(),
			);

		task_manager
			.spawn_handle()
			.spawn("authority-discovery-worker", authority_discovery_worker.run());
	}

	// if the node isn't actively participating in consensus then it doesn't
	// need a keystore, regardless of which protocol we use below.
	let keystore =
		if role.is_authority() { Some(keystore_container.sync_keystore()) } else { None };

	let grandpa_config = sc_finality_grandpa::Config {
		// FIXME #1578 make this available through chainspec
		gossip_duration: Duration::from_millis(333),
		justification_period: 512,
		name: Some(name),
		observer_enabled: false,
		keystore,
		local_role: role,
		telemetry: telemetry.as_ref().map(|x| x.handle()),
	};

	// if enable_grandpa {
	// 	// start the full GRANDPA voter
	// 	// NOTE: non-authorities could run the GRANDPA observer protocol, but at
	// 	// this point the full voter should provide better guarantees of block
	// 	// and vote data availability than the observer. The observer has not
	// 	// been tested extensively yet and having most nodes in a network run it
	// 	// could lead to finality stalls.
	// 	let grandpa_config = sc_finality_grandpa::GrandpaParams {
	// 		config: grandpa_config,
	// 		link: grandpa_link,
	// 		network,
	// 		voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
	// 		prometheus_registry,
	// 		shared_voter_state: SharedVoterState::empty(),
	// 		telemetry: telemetry.as_ref().map(|x| x.handle()),
	// 	};
	//
	// 	// the GRANDPA voter task is considered infallible, i.e.
	// 	// if it fails we take down the service with it.
	// 	task_manager.spawn_essential_handle().spawn_blocking(
	// 		"grandpa-voter",
	// 		sc_finality_grandpa::run_grandpa_voter(grandpa_config)?,
	// 	);
	// }

	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_config = sc_finality_grandpa::GrandpaParams {
			config: grandpa_config,
			link: grandpa_link,
			network: network.clone(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry,
			shared_voter_state,
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("grandpa-voter", sc_finality_grandpa::run_grandpa_voter(grandpa_config)?);
	}

	// network_starter.start_network();
	// Ok(task_manager)

	network_starter.start_network();
	Ok(NewFullBase { task_manager, client, network, transaction_pool })
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration, ares_params: Vec<(&str, Option<Vec<u8>>)>,) -> Result<TaskManager, ServiceError> {
	new_full_base(config, |_, _| (), ares_params).map(|NewFullBase { task_manager, .. }| task_manager)
}

// /// Builds a new service for a light client.
// pub fn new_light(mut config: Configuration) -> Result<TaskManager, ServiceError> {
// 	let telemetry = config
// 		.telemetry_endpoints
// 		.clone()
// 		.filter(|x| !x.is_empty())
// 		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
// 			let worker = TelemetryWorker::new(16)?;
// 			let telemetry = worker.handle().new_telemetry(endpoints);
// 			Ok((worker, telemetry))
// 		})
// 		.transpose()?;
//
// 	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
// 		config.wasm_method,
// 		config.default_heap_pages,
// 		config.max_runtime_instances,
// 	);
//
// 	let (client, backend, keystore_container, mut task_manager, on_demand) =
// 		sc_service::new_light_parts::<Block, RuntimeApi, _>(
// 			&config,
// 			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
// 			executor,
// 		)?;
//
// 	let mut telemetry = telemetry.map(|(worker, telemetry)| {
// 		task_manager.spawn_handle().spawn("telemetry", worker.run());
// 		telemetry
// 	});
//
// 	config.network.extra_sets.push(sc_finality_grandpa::grandpa_peers_set_config());
//
// 	let select_chain = sc_consensus::LongestChain::new(backend.clone());
//
// 	let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
// 		config.transaction_pool.clone(),
// 		config.prometheus_registry(),
// 		task_manager.spawn_essential_handle(),
// 		client.clone(),
// 		on_demand.clone(),
// 	));
//
// 	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
// 		client.clone(),
// 		&(client.clone() as Arc<_>),
// 		select_chain.clone(),
// 		telemetry.as_ref().map(|x| x.handle()),
// 	)?;
//
// 	let slot_duration = sc_consensus_aura::slot_duration(&*client)?.slot_duration();
//
// 	let import_queue =
// 		sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _, _>(ImportQueueParams {
// 			block_import: grandpa_block_import.clone(),
// 			justification_import: Some(Box::new(grandpa_block_import.clone())),
// 			client: client.clone(),
// 			create_inherent_data_providers: move |_, ()| async move {
// 				let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
//
// 				let slot =
// 					sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
// 						*timestamp,
// 						slot_duration,
// 					);
//
// 				Ok((timestamp, slot))
// 			},
// 			spawner: &task_manager.spawn_essential_handle(),
// 			can_author_with: sp_consensus::NeverCanAuthor,
// 			registry: config.prometheus_registry(),
// 			check_for_equivocation: Default::default(),
// 			telemetry: telemetry.as_ref().map(|x| x.handle()),
// 		})?;
//
// 	let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
// 		backend.clone(),
// 		grandpa_link.shared_authority_set().clone(),
// 	));
//
// 	let (network, system_rpc_tx, network_starter) =
// 		sc_service::build_network(sc_service::BuildNetworkParams {
// 			config: &config,
// 			client: client.clone(),
// 			transaction_pool: transaction_pool.clone(),
// 			spawn_handle: task_manager.spawn_handle(),
// 			import_queue,
// 			on_demand: Some(on_demand.clone()),
// 			block_announce_validator_builder: None,
// 			warp_sync: Some(warp_sync),
// 		})?;
//
// 	if config.offchain_worker.enabled {
// 		sc_service::build_offchain_workers(
// 			&config,
// 			task_manager.spawn_handle(),
// 			client.clone(),
// 			network.clone(),
// 		);
// 	}
//
// 	let enable_grandpa = !config.disable_grandpa;
// 	if enable_grandpa {
// 		let name = config.network.node_name.clone();
//
// 		let config = sc_finality_grandpa::Config {
// 			gossip_duration: std::time::Duration::from_millis(333),
// 			justification_period: 512,
// 			name: Some(name),
// 			observer_enabled: false,
// 			keystore: None,
// 			local_role: config.role.clone(),
// 			telemetry: telemetry.as_ref().map(|x| x.handle()),
// 		};
//
// 		task_manager.spawn_handle().spawn_blocking(
// 			"grandpa-observer",
// 			sc_finality_grandpa::run_grandpa_observer(config, grandpa_link, network.clone())?,
// 		);
// 	}
//
// 	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
// 		remote_blockchain: Some(backend.remote_blockchain()),
// 		transaction_pool,
// 		task_manager: &mut task_manager,
// 		on_demand: Some(on_demand),
// 		rpc_extensions_builder: Box::new(|_, _| Ok(())),
// 		config,
// 		client,
// 		keystore: keystore_container.sync_keystore(),
// 		backend,
// 		network,
// 		system_rpc_tx,
// 		telemetry: telemetry.as_mut(),
// 	})?;
//
// 	network_starter.start_network();
// 	Ok(task_manager)
// }


pub fn new_light_base(
	mut config: Configuration,
) -> Result<
	(
		TaskManager,
		RpcHandlers,
		Arc<LightClient>,
		Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
		Arc<
			sc_transaction_pool::LightPool<Block, LightClient, sc_network::config::OnDemand<Block>>,
		>,
	),
	ServiceError,
> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
	);

	let (client, backend, keystore_container, mut task_manager, on_demand) =
		sc_service::new_light_parts::<Block, RuntimeApi, _>(
			&config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;

	let mut telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", worker.run());
		telemetry
	});

	config.network.extra_sets.push(sc_finality_grandpa::grandpa_peers_set_config());

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
		on_demand.clone(),
	));

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;
	let justification_import = grandpa_block_import.clone();

	let (babe_block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::Config::get_or_compute(&*client)?,
		grandpa_block_import,
		client.clone(),
	)?;

	let slot_duration = babe_link.config().slot_duration();
	let import_queue = sc_consensus_babe::import_queue(
		babe_link,
		babe_block_import,
		Some(Box::new(justification_import)),
		client.clone(),
		select_chain.clone(),
		move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

			let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_duration(
					*timestamp,
					slot_duration,
				);

			let uncles =
				sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();

			Ok((timestamp, slot, uncles))
		},
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
		sp_consensus::NeverCanAuthor,
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		grandpa_link.shared_authority_set().clone(),
	));

	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: Some(on_demand.clone()),
			block_announce_validator_builder: None,
			warp_sync: Some(warp_sync),
		})?;

	let enable_grandpa = !config.disable_grandpa;
	if enable_grandpa {
		let name = config.network.node_name.clone();

		let config = sc_finality_grandpa::Config {
			gossip_duration: std::time::Duration::from_millis(333),
			justification_period: 512,
			name: Some(name),
			observer_enabled: false,
			keystore: None,
			local_role: config.role.clone(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		task_manager.spawn_handle().spawn_blocking(
			"grandpa-observer",
			sc_finality_grandpa::run_grandpa_observer(config, grandpa_link, network.clone())?,
		);
	}

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}

	let light_deps = node_rpc::LightDeps {
		remote_blockchain: backend.remote_blockchain(),
		fetcher: on_demand.clone(),
		client: client.clone(),
		pool: transaction_pool.clone(),
	};

	let rpc_extensions = node_rpc::create_light(light_deps);

	let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		on_demand: Some(on_demand),
		remote_blockchain: Some(backend.remote_blockchain()),
		rpc_extensions_builder: Box::new(sc_service::NoopRpcExtensionBuilder(rpc_extensions)),
		client: client.clone(),
		transaction_pool: transaction_pool.clone(),
		keystore: keystore_container.sync_keystore(),
		config,
		backend,
		system_rpc_tx,
		network: network.clone(),
		task_manager: &mut task_manager,
		telemetry: telemetry.as_mut(),
	})?;

	network_starter.start_network();
	Ok((task_manager, rpc_handlers, client, network, transaction_pool))
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
	new_light_base(config).map(|(task_manager, _, _, _, _)| task_manager)
}
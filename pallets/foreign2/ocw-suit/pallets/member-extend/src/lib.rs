#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://substrate.dev/docs/en/knowledgebase/runtime/frame>
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::pallet_prelude::*;
	// use pallet_ocw::{ValidatorHandler};
	use sp_std::vec::Vec;
	use frame_support::sp_runtime::{RuntimeAppPublic, AccountId32};
	use frame_support::traits::ValidatorSet;
	use frame_support::sp_std::fmt::Debug;
	use frame_support::sp_runtime::traits::{IdentifyAccount, IsMember};
	use frame_support::sp_std::convert::TryInto;
	use sp_runtime::app_crypto::sp_core::crypto::UncheckedFrom;

	// type Aura<T> = pallet_aura::Pallet<T>;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config  {
		type MemberAuthority: Member + Parameter + RuntimeAppPublic + Default + Ord + MaybeSerializeDeserialize + UncheckedFrom<[u8; 32]>;
		type Member: IsMember<Self::MemberAuthority>;
		type ValidatorId: IsType<<Self as frame_system::Config>::AccountId>  + Encode + Debug + PartialEq;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	impl<T: Config> IsMember<T::ValidatorId> for Pallet<T>
		// where T::ValidatorId: PartialEq<<T::ValidatorSet as ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>
	{
		fn is_member(authority_id: &T::ValidatorId) -> bool {

			log::info!(" ======BB======= LIN DEBUG:: offchain_worker , author = {:?}", &authority_id);
			let encode_data: Vec<u8> = authority_id.encode();
			assert!(32 == encode_data.len());
			let raw: Result<[u8; 32], _> = encode_data.try_into();
			let raw_data = raw.unwrap();
			let member_authority = T::MemberAuthority::unchecked_from(raw_data);
			log::info!(" ======BB======= LIN DEBUG:: offchain_worker , member_authority = {:?}", &member_authority);
			T::Member::is_member(&member_authority)

		}
	}

}

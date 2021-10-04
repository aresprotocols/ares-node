#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://substrate.dev/docs/en/knowledgebase/runtime/frame>
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*, ConsensusEngineId};
	use frame_system::pallet_prelude::*;
	// use pallet_ocw::{ValidatorHandler};
	use sp_std::vec::Vec;
	use frame_support::sp_runtime::{RuntimeAppPublic, AccountId32};
	use frame_support::sp_runtime::traits::{IsMember, AccountIdConversion};
	use frame_support::traits::{ValidatorSet, FindAuthor};
	use frame_support::sp_std::fmt::Debug;

	// type Aura<T> = pallet_aura::Pallet<T>;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config  {
		// type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type ValidatorId: IsType<<Self as frame_system::Config>::AccountId>  + Encode + Debug + PartialEq;
		type ValidatorSet: ValidatorSet<Self::ValidatorId>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	impl<T: Config > IsMember<T::ValidatorId> for Pallet<T>
		// where T::ValidatorId: PartialEq<<T::ValidatorSet as ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>
		where T::ValidatorId: PartialEq<<T::ValidatorSet as ValidatorSet<<T as frame_system::Config>::AccountId>>::ValidatorId>,
			  T::ValidatorSet: ValidatorSet<<T as frame_system::Config>::AccountId>
	{
		fn is_member(authority_id: &T::ValidatorId) -> bool
		{
			let validator_list = T::ValidatorSet::validators();

			validator_list.iter().any(|id| {
				log::info!("validator_list id = {:?} == author_id = {:?}", & id, &authority_id);
				authority_id == id
			})
		}
	}
}

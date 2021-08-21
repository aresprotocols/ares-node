use super::*;

/// Import the template pallet.
pub use template;

/// Configure the pallet template in pallets/template.
impl template::Config for Runtime {
    type Event = Event;
}


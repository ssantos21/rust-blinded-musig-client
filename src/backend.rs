use electrum_client::{GetBalanceRes, ElectrumApi};

/// return balance of address
pub fn get_address_balance(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> GetBalanceRes {
    electrum_client.script_get_balance(&address.script_pubkey()).unwrap()
}
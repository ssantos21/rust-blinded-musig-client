use electrum_client::{GetBalanceRes, ElectrumApi, GetHistoryRes};

/// return balance of address
pub fn get_address_balance(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> GetBalanceRes {
    electrum_client.script_get_balance(&address.script_pubkey()).unwrap()
}

pub fn get_address_history(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> Vec<GetHistoryRes> {
    electrum_client.script_get_history(&address.script_pubkey()).unwrap()
}
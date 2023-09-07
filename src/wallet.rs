use std::str::FromStr;

use bitcoin::{Address, Network};
use sqlx::{Sqlite, Row};

pub async fn get_all_addresses(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<Address>{
    let query = "SELECT p2tr_address FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut addresses = Vec::<Address>::new();

    for row in rows {

        let p2tr_address = row.get::<String, _>("p2tr_address");
        let address = Address::from_str(&p2tr_address).unwrap().require_network(network).unwrap();
        addresses.push(address);
    }

    addresses
}

pub async fn create_transaction(address: String, amount: u64, network: Network) {

    

}
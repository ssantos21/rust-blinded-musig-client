use bitcoin::{Address, Network};
use secp256k1_zkp::Secp256k1;
use sqlx::{Sqlite, Row};

pub async fn get_all_addresses(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<Address>{
    let query = "SELECT client_pubkey FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut client_pubkeys = Vec::<Address>::new();

    for row in rows {

        let public_key_bytes = row.get::<Vec<u8>, _>("client_pubkey");
        let client_pubkey = secp256k1_zkp::PublicKey::from_slice(&public_key_bytes).unwrap();
        let address = Address::p2tr(&Secp256k1::new(), client_pubkey.x_only_public_key().0, None, network);
        client_pubkeys.push(address);
    }

    client_pubkeys
}
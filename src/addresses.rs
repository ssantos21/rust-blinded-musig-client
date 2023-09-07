use std::str::FromStr;

use rand::RngCore;
use secp256k1_zkp::{ffi::types::AlignedType, Secp256k1, SecretKey, PublicKey};
use bitcoin::{bip32::{ExtendedPrivKey, DerivationPath, ExtendedPubKey, ChildNumber}, Network};
use sqlx::{Sqlite, Row};


pub async fn get_next_bip32_index(pool: &sqlx::Pool<Sqlite>) -> u32 {
    let row = sqlx::query("SELECT MAX(bip32_index) FROM signer_data")
        .fetch_one(pool)
        .await
        .unwrap();

    let index = row.get::<Option<u32>, _>(0);

    if index.is_some() {
        return index.unwrap() + 1;
    } else {
        return 0;
    }
}

pub fn generate_new_key(network: Network, bip32_index: u32) -> (SecretKey, PublicKey) {
    let mut seed = [0u8; 32];  // 256 bits
    rand::thread_rng().fill_bytes(&mut seed);

    println!("Network: {:?}", network);

    // we need secp256k1 context for key derivation
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    // calculate root key from seed
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    println!("Root key: {}", root);

    // derive child xpub
    let path = DerivationPath::from_str("m/514h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    println!("Child at {}: {}", path, child);
    let xpub = ExtendedPubKey::from_priv(&secp, &child);
    println!("Public key at {}: {}", path, xpub);

     // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::from_normal_idx(bip32_index).unwrap();

    let secret_key = child.derive_priv(&secp, &[zero, zero]).unwrap().private_key;
    // let public_key_d = private_key.public_key(&secp);
    // println!("1. Public key at m/0/0: {}", public_key_d.to_string());

    let public_key: secp256k1_zkp::PublicKey = xpub.derive_pub(&secp, &[zero, zero]).unwrap().public_key;
    // println!("2. Public key at m/0/0: {}", public_key.to_string());

    // let address = Address::p2tr(&secp, public_key.x_only_public_key().0, None, network);
    // println!("First receiving address: {}", address);

    (secret_key, public_key)

}
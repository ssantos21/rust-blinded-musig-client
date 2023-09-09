use std::str::FromStr;

use rand::RngCore;
use secp256k1_zkp::{ffi::types::AlignedType, Secp256k1, SecretKey, PublicKey};
use bitcoin::{bip32::{ExtendedPrivKey, DerivationPath, ExtendedPubKey, ChildNumber}, Network, Address};
use sqlx::{Sqlite, Row};


pub async fn generate_or_get_seed(pool: &sqlx::Pool<Sqlite>) -> [u8; 32] {

    let rows = sqlx::query("SELECT * FROM signer_seed")
        .fetch_all(pool)
        .await
        .unwrap();

    if rows.len() > 1 {
        panic!("More than one seed in database");
    }

    if rows.len() == 1 {
        let row = rows.get(0).unwrap();
        let seed = row.get::<Vec<u8>, _>("seed");
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        return seed_array;
    } else {
        let mut seed = [0u8; 32];  // 256 bits
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        
        let query = "INSERT INTO signer_seed (seed) VALUES ($1)";
        let _ = sqlx::query(query)
            .bind(seed.to_vec())
            .execute(pool)
            .await
            .unwrap();

        seed
    }   
}

pub async fn get_next_bip32_index(pool: &sqlx::Pool<Sqlite>, is_change: bool) -> u32 {

    let is_change_i = if is_change { 1 } else { 0 };

    let row = sqlx::query("SELECT MAX(bip32_index) FROM signer_data WHERE is_change = $1")
        .bind(is_change_i)
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

pub async fn generate_new_key(pool: &sqlx::Pool<Sqlite>, network: Network, is_change: bool) -> PublicKey {

    let derivation_path_328 = "m/328h/0h/0h";

    let seed = generate_or_get_seed(pool).await;

    let is_change_i = if is_change { 1 } else { 0 };
    let bip32_index = get_next_bip32_index(&pool, is_change).await;

    // we need secp256k1 context for key derivation
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();

    // calculate root key from seed
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    println!("Root key: {}", root);

    let fingerprint = root.fingerprint(&secp).to_string();

    // derive child xpub
    let path = DerivationPath::from_str(derivation_path_328).unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp, &child);

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let change = ChildNumber::from_normal_idx(is_change_i).unwrap();
    let address_index = ChildNumber::from_normal_idx(bip32_index).unwrap();
    
    let derivation_path = format!("{}/{}/{}", derivation_path_328, change, address_index );

    println!("derivation_path: {}", derivation_path);

    let secret_key = child.derive_priv(&secp, &[change, address_index]).unwrap().private_key;
    // let public_key_d = private_key.public_key(&secp);
    // println!("1. Public key at m/0/0: {}", public_key_d.to_string());

    let public_key: secp256k1_zkp::PublicKey = xpub.derive_pub(&secp, &[change, address_index]).unwrap().public_key;
    // println!("2. Public key at m/0/0: {}", public_key.to_string());

    // let address = Address::p2tr(&secp, public_key.x_only_public_key().0, None, network);
    // println!("First receiving address: {}", address);

    insert_address(pool, &secret_key, &public_key, bip32_index, is_change, &fingerprint, &derivation_path).await;

    public_key

}

pub async fn insert_address(pool: &sqlx::Pool<Sqlite>, client_secret_key: &SecretKey, client_pubkey: &PublicKey, bip32index: u32, is_change: bool, fingerprint: &str, derivation_path: &str)  {

    let query = "INSERT INTO signer_data (bip32_index, client_seckey, client_pubkey, is_change, fingerprint, derivation_path) VALUES ($1, $2, $3, $4, $5, $6)";

    let is_change_i = if is_change { 1 } else { 0 };

    let _ = sqlx::query(query)
        .bind(bip32index)
        .bind(&client_secret_key.secret_bytes().to_vec())
        .bind(&client_pubkey.serialize().to_vec())
        .bind(is_change_i)
        .bind(fingerprint)
        .bind(derivation_path)
        .execute(pool)
        .await
        .unwrap();
}
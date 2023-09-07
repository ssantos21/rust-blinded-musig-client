use std::str::FromStr;

use bitcoin::{hashes::sha256, Network, Address};
use secp256k1_zkp::{PublicKey, SecretKey, Secp256k1, musig::{MusigKeyAggCache, MusigSessionId, MusigPubNonce, MusigAggNonce, BlindingFactor, MusigSession, MusigPartialSignature}, new_musig_nonce_pair, Message, KeyPair, XOnlyPublicKey};
use serde::{Serialize, Deserialize};
use sqlx::{Sqlite, Row};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CError {
    /// Generic error from string error message
    Generic(String)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPublicKeyResponsePayload<'r> {
    server_pubkey: &'r str,
}

pub async fn create_agg_pub_key(pool: &sqlx::Pool<Sqlite>, client_secret_key: &SecretKey, client_pubkey: &PublicKey, bip32index: u32, network: Network) -> Result<(XOnlyPublicKey,Address), CError> {
    let endpoint = "http://127.0.0.1:8000";
    let path = "server_pubkey";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", endpoint, path));

    let value = match request.json(&{}).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        },
        Err(err) => {
            return Err(CError::Generic(err.to_string()));
        },
    };

    let response: ServerPublicKeyResponsePayload = serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str()));

    let server_pubkey = PublicKey::from_str(&response.server_pubkey.to_string()).unwrap();

    // let client_secret_key: SecretKey = SecretKey::new(&mut rand::thread_rng());

    let secp = Secp256k1::new();
    
    // let client_pubkey: PublicKey = client_secret_key.public_key(&secp);

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[*client_pubkey, server_pubkey]);
    let agg_pk = key_agg_cache.agg_pk();

    let address = Address::p2tr(&Secp256k1::new(), agg_pk, None, network);

    let query = "INSERT INTO signer_data (bip32_index, client_seckey, client_pubkey, server_pubkey, aggregated_key, p2tr_address) VALUES ($1, $2, $3, $4, $5, $6)";

    let _ = sqlx::query(query)
        .bind(bip32index)
        .bind(&client_secret_key.secret_bytes().to_vec())
        .bind(&client_pubkey.serialize().to_vec())
        .bind(&server_pubkey.serialize().to_vec())
        .bind(&agg_pk.serialize().to_vec())
        .bind(&address.to_string())
        .execute(pool)
        .await
        .unwrap();

    Ok((agg_pk, address))

}

pub async fn list_agg_pub_keys(pool: &sqlx::Pool<Sqlite>) -> Result<Vec<String>, CError> {
    // Query to fetch data
    let rows = sqlx::query("SELECT aggregated_key FROM signer_data")
        .fetch_all(pool)
        .await
        .unwrap();

    let mut aggregated_pubkeys = Vec::<String>::new();

    for row in rows {
        let public_key_bytes = row.get::<Option<Vec<u8>>, _>("aggregated_key");

        if public_key_bytes.is_some() {
            let aggregated_pubkey = secp256k1_zkp::XOnlyPublicKey::from_slice(&public_key_bytes.unwrap()).unwrap();
            aggregated_pubkeys.push(aggregated_pubkey.to_string());
        }
    }

    Ok(aggregated_pubkeys)
}

#[derive(Serialize, Deserialize)]
pub struct PublicNonceRequestPayload<'r> {
    server_public_key: &'r str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPublicNonceResponsePayload<'r> {
    server_pubnonce: &'r str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialSignatureRequestPayload<'r> {
    server_public_key: &'r str,
    keyaggcoef: &'r str,
    negate_seckey: bool,
    session: &'r str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialSignatureResponsePayload<'r> {
    partial_sig: &'r str,
}

pub async fn sign_message(pool: &sqlx::Pool<Sqlite>, agg_pub_key: String, message: String) -> Result<String, CError> {

    let agg_pub_key_bytes = hex::decode(agg_pub_key).unwrap();

    let query = "SELECT client_seckey, client_pubkey, server_pubkey FROM signer_data WHERE aggregated_key = $1";

    let row = sqlx::query(query)
        .bind(&agg_pub_key_bytes)
        .fetch_one(pool)
        .await
        .unwrap();

    let client_seckey_bytes = row.get::<Option<Vec<u8>>, _>("client_seckey").unwrap();
    let client_pubkey_bytes = row.get::<Option<Vec<u8>>, _>("client_pubkey").unwrap();
    let server_pubkey_bytes = row.get::<Option<Vec<u8>>, _>("server_pubkey").unwrap();

    let client_seckey = secp256k1_zkp::SecretKey::from_slice(&client_seckey_bytes).unwrap();
    let client_pubkey = secp256k1_zkp::PublicKey::from_slice(&client_pubkey_bytes).unwrap();
    let server_pubkey = secp256k1_zkp::PublicKey::from_slice(&server_pubkey_bytes).unwrap();

    let client_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let secp = Secp256k1::new();

    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(&secp, client_session_id, None, Some(client_seckey), client_pubkey, None, None).unwrap();

    let endpoint = "http://127.0.0.1:8000";
    let path = "public_nonce";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", endpoint, path));

    let payload = PublicNonceRequestPayload {
        server_public_key: &server_pubkey.to_string(),
    };

    let value = match request.json(&payload).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        },
        Err(err) => {
            return Err(CError::Generic(err.to_string()));
        },
    };

    let response: ServerPublicNonceResponsePayload = serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str()));

    let server_pub_nonce_bytes = hex::decode(response.server_pubnonce).unwrap();
    
    let server_pub_nonce = MusigPubNonce::from_slice(server_pub_nonce_bytes.as_slice()).unwrap();

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[client_pubkey, server_pubkey]);

    let msg = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());

    let aggnonce = MusigAggNonce::new(&secp, &[client_pub_nonce, server_pub_nonce]);

    let blinding_factor = BlindingFactor::new(&mut rand::thread_rng());

    let session = MusigSession::new_blinded(
        &secp,
        &key_agg_cache,
        aggnonce,
        msg,
        &blinding_factor
    );

    let client_keypair = KeyPair::from_secret_key(&secp, &client_seckey);

    let client_partial_sig = session.partial_sign(
        &secp,
        client_sec_nonce,
        &client_keypair,
        &key_agg_cache,
    ).unwrap();

    assert!(session.partial_verify(
        &secp,
        &key_agg_cache,
        client_partial_sig,
        client_pub_nonce,
        client_pubkey,
    ));

    let (key_agg_coef, negate_seckey) = session.get_keyaggcoef_and_negation_seckey(&secp, &key_agg_cache, &server_pubkey);

    let payload = PartialSignatureRequestPayload {
        server_public_key: &server_pubkey.to_string(),
        keyaggcoef: &hex::encode(key_agg_coef.serialize()),
        negate_seckey,
        session: &hex::encode(session.serialize()),
    };

    let endpoint = "http://127.0.0.1:8000";
    let path = "partial_signature";

    let client: reqwest::Client = reqwest::Client::new();
    let request = client.post(&format!("{}/{}", endpoint, path));

    let value = match request.json(&payload).send().await {
        Ok(response) => {
            let text = response.text().await.unwrap();
            text
        },
        Err(err) => {
            return Err(CError::Generic(err.to_string()));
        },
    };

    let response: PartialSignatureResponsePayload = serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str()));

    let server_partial_sig_bytes = hex::decode(response.partial_sig).unwrap();

    let server_partial_sig = MusigPartialSignature::from_slice(server_partial_sig_bytes.as_slice()).unwrap();

    assert!(session.partial_verify(
        &secp,
        &key_agg_cache,
        server_partial_sig,
        server_pub_nonce,
        server_pubkey,
    ));

    let schnorr_sig = session.partial_sig_agg(&[client_partial_sig, server_partial_sig]);
    let agg_pk = key_agg_cache.agg_pk();

    assert!(secp.verify_schnorr(&schnorr_sig, &msg, &agg_pk).is_ok());

    Ok(schnorr_sig.to_string())
}
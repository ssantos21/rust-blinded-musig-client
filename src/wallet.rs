use std::{str::FromStr, collections::{HashMap, BTreeMap}};

use bitcoin::{Address, Network, TxOut, OutPoint, TxIn, ScriptBuf, Witness, Transaction, absolute, psbt::{Psbt, Input, PsbtSighashType, self}, Amount, sighash::{TapSighashType, SighashCache, self, TapSighash}, taproot::{TapLeafHash, self, TapTweakHash}, secp256k1, key::TapTweak, hashes::{sha256, Hash}};
use secp256k1_zkp::{SecretKey, XOnlyPublicKey, Secp256k1, PublicKey, Message, musig::{MusigSessionId, MusigPubNonce, MusigKeyAggCache, MusigAggNonce, BlindingFactor, MusigSession, MusigPartialSignature}, new_musig_nonce_pair, KeyPair, schnorr::Signature};
use serde::{Serialize, Deserialize};
use sqlx::{Sqlite, Row};

pub async fn get_all_addresses(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<Address>{
    let query = "SELECT p2tr_agg_address FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut addresses = Vec::<Address>::new();

    for row in rows {

        let p2tr_agg_address = row.get::<String, _>("p2tr_agg_address");
        let address = Address::from_str(&p2tr_agg_address).unwrap().require_network(network).unwrap();
        addresses.push(address);
    }

    addresses
}

pub async fn get_all_addresses_info(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<(Address, SecretKey, PublicKey, PublicKey, XOnlyPublicKey)>{
    let query = "SELECT p2tr_agg_address, client_seckey, client_pubkey, server_pubkey, aggregated_pubkey FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut addresses = Vec::<(Address, SecretKey, PublicKey, PublicKey, XOnlyPublicKey)>::new();

    for row in rows {

        let p2tr_agg_address = row.get::<String, _>("p2tr_agg_address");
        let address = Address::from_str(&p2tr_agg_address).unwrap().require_network(network).unwrap();

        let client_seckey_bytes = row.get::<Vec<u8>, _>("client_seckey");
        let client_seckey = SecretKey::from_slice(&client_seckey_bytes).unwrap();

        let client_pubkey_bytes = row.get::<Vec<u8>, _>("client_pubkey");
        let client_pubkey = PublicKey::from_slice(&client_pubkey_bytes).unwrap();

        let server_pubkey_bytes = row.get::<Vec<u8>, _>("server_pubkey");
        let server_pubkey = PublicKey::from_slice(&server_pubkey_bytes).unwrap();

        let aggregated_pubkey_bytes = row.get::<Vec<u8>, _>("aggregated_pubkey");
        let xonly_aggregated_pubkey = XOnlyPublicKey::from_slice(&aggregated_pubkey_bytes).unwrap();

        addresses.push((address, client_seckey, client_pubkey, server_pubkey, xonly_aggregated_pubkey));
    }

    addresses
}

pub struct UTXOInfo {

    pub address: Address,

    pub client_seckey: SecretKey,

    pub client_pubkey: PublicKey,

    pub server_pubkey: PublicKey,

    pub aggregated_pubkey: XOnlyPublicKey,
    /// Confirmation height of the transaction that created this output.
    pub height: usize,
    /// Txid of the transaction
    pub tx_hash: bitcoin::Txid,
    /// Index of the output in the transaction.
    pub tx_pos: usize,
    /// Value of the output.
    pub value: u64,
}

pub async fn create_transaction(inputs_info: &Vec::<UTXOInfo>, outputs: &Vec<TxOut>) -> Result<(Transaction, Transaction), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    let mut tx_inputs = Vec::<bitcoin::TxIn>::new();

    let mut mapped_utxos = HashMap::new();

    for input in inputs_info {
        mapped_utxos.insert(input.aggregated_pubkey, input);
    }

    for input in inputs_info {
        let input_utxo = OutPoint { txid: input.tx_hash, vout: input.tx_pos as u32 };
        let input = TxIn {
            previous_output: input_utxo,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        };
        tx_inputs.push(input);
    }

    let tx1 = Transaction {
        version: 2,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: outputs.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx1).unwrap();

    let mut psbt_inputs = Vec::<Input>::new();

    for input_info in inputs_info {

        println!("input_info.address: {}", input_info.address.to_string());
        println!("input_info.address.script_pubkey: {}", input_info.address.script_pubkey().to_hex_string());
        println!("input_info.value: {}", input_info.value);

        let mut input = Input {
            witness_utxo: {
                let script_pubkey = input_info.address.script_pubkey();
                let amount = Amount::from_sat(input_info.value);
    
                Some(TxOut { value: amount.to_sat(), script_pubkey })
            },
            ..Default::default()
        };
        let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
        input.sighash_type = Some(ty);
        input.tap_internal_key = Some(input_info.aggregated_pubkey);
        psbt_inputs.push(input);
    }

    psbt.inputs = psbt_inputs;

   
    let unsigned_tx = psbt.unsigned_tx.clone();
    for (vout, input) in psbt.inputs.iter_mut().enumerate() {

        let hash_ty = input
            .sighash_type
            .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
            .unwrap_or(TapSighashType::All);

        let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
            vout,
            &sighash::Prevouts::All(&[TxOut {
                value: input.witness_utxo.as_ref().unwrap().value,
                script_pubkey: input.witness_utxo.as_ref().unwrap().script_pubkey.clone(),
            }]),
            hash_ty,
        ).unwrap();

        let utxo_info = mapped_utxos.get(&input.tap_internal_key.ok_or("Internal key missing in PSBT")?).unwrap();

        let sig = musig_sign_psbt_taproot(
            &utxo_info.client_seckey,
            &utxo_info.client_pubkey,
            &utxo_info.server_pubkey,
            &utxo_info.aggregated_pubkey,
            hash,
            &secp,
        ).await.unwrap();

        println!("sig: {}", sig.to_string());

        let final_signature = taproot::Signature { sig, hash_ty };

        input.tap_key_sig = Some(final_signature);
    }

    // FINALIZER
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    let tx = psbt.extract_tx();
    
    //let mut prev_out_verify = Vec::<bitcoin::TxOut>::new();
    for input in inputs_info {
        let script_pubkey_hex = input.address.script_pubkey().to_hex_string();
        let amount = Amount::from_sat(input.value);

        //prev_out_verify.push(TxOut { value: amount.to_sat(), script_pubkey });
        tx.verify(|_| {
            Some(TxOut { 
                value: amount.to_sat(), 
                script_pubkey: ScriptBuf::from_hex(&script_pubkey_hex).unwrap() 
            })
        })
        .expect("failed to verify transaction");
    }

    Ok((tx, unsigned_tx))
}

/*
fn sign_psbt_taproot(
    secret_key: &SecretKey,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    hash_ty: TapSighashType,
    secp: &Secp256k1<secp256k1::All>,
) {
    let keypair = secp256k1::KeyPair::from_seckey_slice(secp, secret_key.as_ref()).unwrap();
    let keypair = match leaf_hash {
        None => keypair.tap_tweak(secp, psbt_input.tap_merkle_root).to_inner(),
        Some(_) => keypair, // no tweak for script spend
    };

    let sig = secp.sign_schnorr(&hash.into(), &keypair);

    let final_signature = taproot::Signature { sig, hash_ty };

    if let Some(lh) = leaf_hash {
        psbt_input.tap_script_sigs.insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}
 */

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CError {
    /// Generic error from string error message
    Generic(String)
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

/* async fn musig_sign_psbt_taproot(
    client_seckey: &SecretKey,
    client_pubkey: &PublicKey,
    server_pubkey: &PublicKey,
    aggregated_pubkey: &XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    hash_ty: TapSighashType,
    secp: &Secp256k1<secp256k1::All>,
)  -> Result<(), CError>  {
    let msg: Message = hash.into();

    let client_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(&secp, client_session_id, None, Some(client_seckey.to_owned()), client_pubkey.to_owned(), None, None).unwrap();

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

    println!("response.server_pubnonce: {}", response.server_pubnonce);

    let server_pub_nonce_bytes = hex::decode(response.server_pubnonce).unwrap();
    
    let server_pub_nonce = MusigPubNonce::from_slice(server_pub_nonce_bytes.as_slice()).unwrap();

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[client_pubkey.to_owned(), server_pubkey.to_owned()]);

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
        client_pubkey.to_owned(),
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

    println!("response.partial_sig: {}", response.partial_sig);
    let server_partial_sig_bytes = hex::decode(response.partial_sig).unwrap();

    let server_partial_sig = MusigPartialSignature::from_slice(server_partial_sig_bytes.as_slice()).unwrap();

    assert!(session.partial_verify(
        &secp,
        &key_agg_cache,
        server_partial_sig,
        server_pub_nonce,
        server_pubkey.to_owned(),
    ));

    let sig = session.partial_sig_agg(&[client_partial_sig, server_partial_sig]);
    let agg_pk = key_agg_cache.agg_pk();

    assert!(agg_pk.eq(aggregated_pubkey));

    assert!(secp.verify_schnorr(&sig, &msg, &agg_pk).is_ok());

    let final_signature = taproot::Signature { sig, hash_ty };

    println!("aggregated_pubkey: {}", aggregated_pubkey.to_string());
    println!("agg_pk: {}           ", agg_pk .to_string());

    let sig_hex =  hex::encode(sig.as_ref());
    println!("final_signature: {}", sig_hex);

    if let Some(lh) = leaf_hash {
        psbt_input.tap_script_sigs.insert((agg_pk, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
    
    Ok(())

}
 */

 async fn musig_sign_psbt_taproot(
    client_seckey: &SecretKey,
    client_pubkey: &PublicKey,
    server_pubkey: &PublicKey,
    aggregated_pubkey: &XOnlyPublicKey,
    hash: TapSighash,
    secp: &Secp256k1<secp256k1::All>,
)  -> Result<Signature, CError>  {
    let msg: Message = hash.into();

    // let msg = Message::from_hashed_data::<sha256::Hash>(hash.as_ref());

    let msg_hex = hex::encode(msg.as_ref());
    println!("msg: {}", msg_hex);

    let client_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let (client_sec_nonce, client_pub_nonce) = new_musig_nonce_pair(&secp, client_session_id, None, Some(client_seckey.to_owned()), client_pubkey.to_owned(), None, None).unwrap();

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

    let mut key_agg_cache = MusigKeyAggCache::new(&secp, &[client_pubkey.to_owned(), server_pubkey.to_owned()]);

    let tap_tweak = TapTweakHash::from_key_and_tweak(key_agg_cache.agg_pk(), None);
    let tap_tweak_bytes = tap_tweak.as_byte_array();

    // tranform tweak: Scalar to SecretKey
    let tweak = SecretKey::from_slice(tap_tweak_bytes).unwrap();

    let tweaked_pubkey = key_agg_cache.pubkey_xonly_tweak_add(secp, tweak).unwrap();

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
        client_pubkey.to_owned(),
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
        server_pubkey.to_owned(),
    ));

    let sig = session.partial_sig_agg(&[client_partial_sig, server_partial_sig]);
    let agg_pk = key_agg_cache.agg_pk();

    assert!(agg_pk.eq(aggregated_pubkey));

    assert!(secp.verify_schnorr(&sig, &msg, &tweaked_pubkey.x_only_public_key().0).is_ok());

    println!("aggregated_pubkey: {}", aggregated_pubkey.to_string());
    println!("agg_pk: {}           ", agg_pk .to_string());
   
    Ok(sig)
}
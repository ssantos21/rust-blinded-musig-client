use std::{str::FromStr, collections::{HashMap, BTreeMap}};

use bitcoin::{Address, Network, TxOut, OutPoint, TxIn, ScriptBuf, Witness, Transaction, absolute, psbt::{Psbt, Input, PsbtSighashType, self}, Amount, sighash::{TapSighashType, SighashCache, self, TapSighash}, taproot::{TapLeafHash, self}, secp256k1, key::TapTweak};
use secp256k1_zkp::{SecretKey, XOnlyPublicKey, Secp256k1, PublicKey, Message, musig::MusigSessionId, new_musig_nonce_pair};
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

pub async fn create_transaction(inputs_info: &Vec::<UTXOInfo>, outputs: &Vec<TxOut>) -> Result<Transaction, Box<dyn std::error::Error>> {
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

    // SIGNER
    let unsigned_tx = psbt.unsigned_tx.clone();
    psbt.inputs.iter_mut().enumerate().try_for_each::<_, Result<(), Box<dyn std::error::Error>>>(
        |(vout, input)| {

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

            sign_psbt_taproot(
                &utxo_info.client_seckey,
                input.tap_internal_key.unwrap(),
                None,
                input,
                hash,
                hash_ty,
                &secp,
            );

            Ok(())
        },
    ).unwrap();

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

    Ok(tx)

}

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

async fn musig_sign_psbt_taproot(
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

    Ok(())

}

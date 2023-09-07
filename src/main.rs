mod musig;
mod addresses;
mod backend;
mod wallet;

use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use serde_json::json;
use sqlx::{SqlitePool, Sqlite, migrate::MigrateDatabase};

use crate::{addresses::{generate_new_key, get_next_bip32_index}, wallet::get_all_addresses};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create Aggregated Public Key
    CreateAggPubKey {},
    /// List Aggregated Public Keys
    ListAggPubKeys {},
    /// Sign Message
    SignMessage { agg_pub_key: String, message: String },
    /// Get a wallet balance
    GetBalance { },
    /// List transactions
    ListTransactions { },
    /// Send coin to an address
    Send { address: String, amount: u64 },
    
}

#[tokio::main(flavor = "current_thread")]
async fn main() {

    // let network = bitcoin::Network::Bitcoin;
    let network = bitcoin::Network::Signet;

    let client = electrum_client::Client::new("tcp://127.0.0.1:50001").unwrap();

    let cli = Cli::parse();

    if !Sqlite::database_exists("wallet.db").await.unwrap_or(false) {
        match Sqlite::create_database("wallet.db").await {
            Ok(_) => println!("Create db success"),
            Err(error) => panic!("error: {}", error),
        }
    }

    let pool = SqlitePool::connect("wallet.db").await.unwrap();

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap();

    match cli.command {
        Commands::CreateAggPubKey {} => {

            let bip32_index = get_next_bip32_index(&pool).await;
            println!("Next index: {}", bip32_index);

            let (secret_key, public_key) = generate_new_key(network, bip32_index);

            let (aggregated_pubkey, address) = 
                musig::create_agg_pub_key(&pool, &secret_key, &public_key, bip32_index, network).await.unwrap();
            
            let res = json!({
                "aggregated_pubkey_address": aggregated_pubkey.to_string(),
                "address": address
            });
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Commands::ListAggPubKeys {} => {
            let aggregated_pubkeys = musig::list_agg_pub_keys(&pool).await.unwrap();
            let res = json!({
                "aggregated_pubkeys": aggregated_pubkeys
            });
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Commands::SignMessage { agg_pub_key, message } => {
            let signature = musig::sign_message(&pool, agg_pub_key, message).await.unwrap();
            let res = json!({
                "signature": signature
            });
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Commands::GetBalance {  } => {

            #[derive(Serialize, Deserialize, Debug)]
            struct Balance {
                address: String,
                balance: u64,
                unconfirmed_balance: i64,
            }

            let addresses = get_all_addresses(&pool, network).await;
            let result: Vec<Balance> = addresses.iter().map(|address| {
                let balance_res = backend::get_address_balance(&client, &address);
                Balance {
                    address: address.to_string(),
                    balance: balance_res.confirmed,
                    unconfirmed_balance: balance_res.unconfirmed,
                }
            }).collect();

            println!("{}", serde_json::to_string_pretty(&json!(result)).unwrap());
        },
        Commands::ListTransactions { } => {

            #[derive(Serialize, Deserialize, Debug)]
            struct History {
                address: String,
                tx_hash: String,
                height: i32,
            }

            let addresses = get_all_addresses(&pool, network).await;
            let mut result: Vec<History> = Vec::new();

            for address in addresses {
                let history_vector = backend::get_address_history(&client, &address);
                for history in history_vector {
                    result.push(History {
                        address: address.to_string(),
                        tx_hash: history.tx_hash.to_string(),
                        height: history.height,
                    });
                }
            }
            
            println!("{}", serde_json::to_string_pretty(&json!(result)).unwrap());
        },
        Commands::Send { address, amount } => {
            // let txid = backend::send_to_address(&client, &address, amount).await;
            // println!("{}", txid);
        }
    }

    pool.close().await;
}

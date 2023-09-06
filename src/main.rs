mod musig;
mod addresses;

use bitcoin::Address;
use clap::{Parser, Subcommand};
use secp256k1_zkp::Secp256k1;
use serde_json::json;
use sqlx::{SqlitePool, Sqlite, migrate::MigrateDatabase};

use crate::addresses::{generate_new_key, get_next_bip32_index};

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
}

#[tokio::main(flavor = "current_thread")]
async fn main() {

    let network = bitcoin::Network::Bitcoin;

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

            let aggregated_pubkey = musig::create_agg_pub_key(&pool, &secret_key, &public_key, bip32_index).await.unwrap();
            let address = Address::p2tr(&Secp256k1::new(), aggregated_pubkey, None, network);
            
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
    }

    pool.close().await;
}

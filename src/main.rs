mod musig;


use clap::{Parser, Subcommand};
use serde_json::json;
use sqlx::{SqlitePool, Sqlite, migrate::MigrateDatabase};

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
            let aggregated_pubkey = musig::create_agg_pub_key(&pool).await.unwrap();
            let res = json!({
                "aggregated_pubkey": aggregated_pubkey
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

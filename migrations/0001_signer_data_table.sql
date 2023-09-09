CREATE TABLE IF NOT EXISTS signer_seed (
    seed BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signer_data (
    bip32_index INT,
    client_seckey BLOB UNIQUE,
    client_pubkey BLOB UNIQUE,
    server_pubkey BLOB,
    aggregated_pubkey BLOB,
    p2tr_agg_address TEXT,
    is_change INT,
    fingerprint TEXT,
    derivation_path TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
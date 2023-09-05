CREATE TABLE IF NOT EXISTS signer_data (
    client_seckey BLOB,
    client_pubkey BLOB,
    server_pubkey BLOB,
    aggregated_key BLOB,
    cache BLOB
);
pub use tokio_postgres;

use tokio_postgres::{Client, NoTls};

/// Connects to a postgres server (or a shotover proxy in front of one) on localhost,
/// retrying until the server is ready to accept connections.
pub async fn postgres_connection(port: u16) -> Client {
    let config =
        format!("host=127.0.0.1 port={port} user=postgres password=shotover dbname=postgres");
    for _ in 0..120 {
        match tokio_postgres::connect(&config, NoTls).await {
            Ok((client, connection)) => {
                tokio::spawn(async move {
                    // The connection task finishes with an error on unclean shutdown,
                    // which tests trigger deliberately, so the result is discarded.
                    let _ = connection.await;
                });
                return client;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    panic!("postgres at 127.0.0.1:{port} never became ready");
}

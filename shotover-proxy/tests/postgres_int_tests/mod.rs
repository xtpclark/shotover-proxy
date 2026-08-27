use crate::shotover_process;
use pretty_assertions::assert_eq;
use test_helpers::connection::postgres::postgres_connection;
use test_helpers::docker_compose::docker_compose;

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_standard() {
    let _compose = docker_compose("tests/test-configs/postgres/passthrough/docker-compose.yaml");
    let shotover = shotover_process("tests/test-configs/postgres/passthrough/topology.yaml")
        .start()
        .await;

    let client = postgres_connection(15432).await;

    // Simple values through the extended protocol (tokio-postgres always uses it).
    let rows = client
        .query("SELECT 1::int4 AS one, 'text'::text AS two", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i32>("one"), 1);
    assert_eq!(rows[0].get::<_, String>("two"), "text");

    // Prepared statement reused with different parameters.
    let statement = client
        .prepare("SELECT $1::int4 + $2::int4")
        .await
        .unwrap();
    for (a, b) in [(1, 2), (40, 2), (-1, 1)] {
        let rows = client.query(&statement, &[&a, &b]).await.unwrap();
        assert_eq!(rows[0].get::<_, i32>(0), a + b);
    }

    // DDL and writes.
    client
        .batch_execute(
            "CREATE TABLE shotover_test (id int4 PRIMARY KEY, name text);
             INSERT INTO shotover_test VALUES (1, 'one'), (2, 'two'), (3, NULL);",
        )
        .await
        .unwrap();
    let rows = client
        .query("SELECT id, name FROM shotover_test ORDER BY id", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2].get::<_, Option<String>>("name"), None);

    // A failing statement mid-connection must return the server error and
    // leave the connection usable (error-skip-to-Sync recovery).
    let err = client
        .query("SELECT * FROM missing_table", &[])
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("missing_table"),
        "unexpected error: {err}"
    );
    let rows = client.query("SELECT 2::int4", &[]).await.unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 2);

    // An error inside an explicit transaction, then rollback and reuse.
    client.batch_execute("BEGIN").await.unwrap();
    client
        .query("SELECT 1/0", &[])
        .await
        .unwrap_err();
    client.batch_execute("ROLLBACK").await.unwrap();
    let rows = client.query("SELECT 3::int4", &[]).await.unwrap();
    assert_eq!(rows[0].get::<_, i32>(0), 3);

    // COPY FROM STDIN.
    let sink = client
        .copy_in("COPY shotover_test FROM STDIN")
        .await
        .unwrap();
    futures::pin_mut!(sink);
    use futures::SinkExt;
    sink.send(bytes::Bytes::from_static(b"4\tfour\n5\tfive\n"))
        .await
        .unwrap();
    let copied = sink.finish().await.unwrap();
    assert_eq!(copied, 2);

    // COPY TO STDOUT.
    use futures::TryStreamExt;
    let out = client
        .copy_out("COPY shotover_test TO STDOUT")
        .await
        .unwrap();
    let bytes: Vec<bytes::Bytes> = out.try_collect().await.unwrap();
    let total: usize = bytes.iter().map(|b| b.len()).sum();
    assert!(total > 0, "COPY TO STDOUT returned no data");

    client
        .batch_execute("DROP TABLE shotover_test")
        .await
        .unwrap();

    shotover.shutdown_and_then_consume_events(&[]).await;
}

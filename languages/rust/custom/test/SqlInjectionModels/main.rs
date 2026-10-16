use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use std::fs;
use warp::Filter;

diesel::table! {
    some_table (id) {
        id -> Integer,
        key -> Text,
    }
}

#[derive(QueryableByName, Debug)]
#[diesel(table_name = some_table)]
pub struct DbItem {
    id: i32,
    key: String,
}

// Warp path parameter (remote) formatted into a SQLx query inside an `async move` block
// returned from the `then` closure. The `warp` source and `sqlx` sink are both modeled
// upstream, but taint captured by the returned (and never locally awaited) async block
// does not reach its body, so this is a dataflow limitation rather than a missing model.
async fn warp_then_sqlx() {
    let route = warp::path::param().then(|tainted_param: String| async move {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let unsafe_query = format!("SELECT * FROM t WHERE key = '{}'", tainted_param);
        let _ = sqlx::query(&unsafe_query).fetch_one(&pool).await; // $ MISSING: Alert[rust/sql-injection]
        // GOOD: bound parameter
        let _ = sqlx::query("SELECT * FROM t WHERE key = ?").bind(&tainted_param).fetch_one(&pool).await;
        "ok"
    });
    warp::serve(route).run(([127, 0, 0, 1], 3030)).await;
}

// File content (local `file` threat model) formatted into a `postgres` query. Covered by the
// upstream `postgres` models once the `local` (or `file`) threat model is enabled.
fn postgres_file() -> Result<(), postgres::Error> {
    let db_key = fs::read_to_string("/var/tmp/tainted_file.txt").unwrap(); // $ Source=pg
    let mut client = postgres::Client::connect("host=localhost user=postgres", postgres::NoTls)?;
    let unsafe_query = format!("SELECT foo FROM bar WHERE baz = {}", db_key);
    for row in client.query(&unsafe_query, &[])? { // $ Alert[rust/sql-injection]=pg
        let _foo: i32 = row.get("foo");
    }
    // GOOD: bound parameter
    let _ = client.query("SELECT foo FROM bar WHERE baz = $1", &[&db_key])?;
    Ok(())
}

// File content (local `file` threat model) used to build Diesel raw SQL.
fn diesel_file() {
    let mut conn = SqliteConnection::establish("/var/tmp/database.db").unwrap();
    let db_key = fs::read_to_string("/var/tmp/tainted_file.txt").unwrap(); // $ Source=diesel
    let unsafe_query = "SELECT * FROM some_table WHERE key = '".to_owned() + db_key.trim() + "'";
    let _ = diesel::sql_query(unsafe_query).load::<DbItem>(&mut conn); // $ Alert[rust/sql-injection]=diesel
    let _ = diesel::dsl::sql_query(format!("SELECT * FROM some_table WHERE key = '{}'", db_key)) // $ Alert[rust/sql-injection]=diesel
        .load::<DbItem>(&mut conn);
    let _ = diesel::sql_query("SELECT * FROM some_table WHERE ")
        .sql(format!("key = '{}'", db_key)) // $ Alert[rust/sql-injection]=diesel
        .load::<DbItem>(&mut conn);
    let _ = some_table::table
        .filter(diesel::dsl::sql::<diesel::sql_types::Bool>(&format!("key = '{}'", db_key))) // $ Alert[rust/sql-injection]=diesel
        .select(some_table::id)
        .load::<i32>(&mut conn);
    let _ = conn.batch_execute(&format!("DELETE FROM some_table WHERE key = '{}'", db_key)); // $ Alert[rust/sql-injection]=diesel
    // A `&str` produced by `trim()` does not propagate taint through `format!`; this is a
    // standard library dataflow gap independent of the Diesel sink model.
    let _ = diesel::sql_query(format!("SELECT * FROM some_table WHERE key = '{}'", db_key.trim())) // $ MISSING: Alert[rust/sql-injection]=diesel
        .load::<DbItem>(&mut conn);
    // GOOD: bound parameters / static SQL
    let _ = diesel::sql_query("SELECT * FROM some_table WHERE key = ?")
        .bind::<diesel::sql_types::Text, _>(db_key.trim())
        .load::<DbItem>(&mut conn);
    let _ = some_table::table
        .filter(some_table::key.eq(db_key.trim()))
        .select(some_table::id)
        .load::<i32>(&mut conn);
    let _ = conn.batch_execute("DELETE FROM some_table WHERE id = 1");
}

// Warp path parameter (remote) passed to Diesel raw SQL from a `map` closure.
async fn warp_map_diesel() {
    let route = warp::path::param().map(|tainted_param: String| {
        let mut conn = SqliteConnection::establish("/var/tmp/database.db").unwrap();
        let _ = diesel::sql_query(format!("SELECT * FROM some_table WHERE key = '{}'", tainted_param)) // $ Alert[rust/sql-injection]=warp
            .load::<DbItem>(&mut conn);
        // GOOD: bound parameter
        let _ = diesel::sql_query("SELECT * FROM some_table WHERE key = ?")
            .bind::<diesel::sql_types::Text, _>(&tainted_param)
            .load::<DbItem>(&mut conn);
        "ok"
    }); // $ Source=warp
    warp::serve(route).run(([127, 0, 0, 1], 3031)).await;
}

#[tokio::main]
async fn main() {
    let _ = postgres_file();
    diesel_file();
    warp_map_diesel().await;
    warp_then_sqlx().await;
}

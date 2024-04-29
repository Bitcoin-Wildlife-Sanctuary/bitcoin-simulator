use anyhow::Result;
use bitcoin::consensus::Encodable;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Database {
    pub conn: Connection,
}

impl Database {
    pub fn create_connection<P: AsRef<Path>>(path: P) -> Result<Database> {
        let conn = Connection::open(path)?;

        Ok(Database { conn })
    }

    pub fn reset(&self) -> Result<()> {
        self.conn.execute_batch(
            "DROP TABLE outputs;
                CREATE TABLE outputs
                (
                    tx_id          TEXT              not null,
                    output_id      integer           not null,
                    value          integer           not null,
                    script_pub_key BLOB              not null,
                    is_spent       INTEGER default 0 not null,
                    constraint outputs_pk
                        primary key (tx_id, output_id)
                );
                DROP TABLE transactions;
                CREATE TABLE \"transactions\"
                (
                    tx_id       TEXT    not null
                        constraint txid
                            primary key,
                    num_outputs integer not null,
                    body        blob    not null
                );
            ",
        )?;
        Ok(())
    }

    pub fn mark_output_as_spent(&self, tx_id: &str, output_id: usize) -> Result<()> {
        self.conn.execute(
            "UPDATE outputs SET is_spent = 1 WHERE tx_id = ?1 and output_id = ?2",
            params![tx_id, output_id],
        )?;
        Ok(())
    }

    pub fn insert_transaction_unconditionally(&self, tx: &bitcoin::Transaction) -> Result<()> {
        let tx_id = tx.compute_txid().to_string();

        let num_outputs = tx.output.len();

        let mut body = Vec::new();
        tx.consensus_encode(&mut body)?;

        self.conn.execute(
            "INSERT INTO \"transactions\" (tx_id, num_outputs, body) VALUES (?1, ?2, ?3)",
            params![tx_id, num_outputs, body],
        )?;

        Ok(())
    }
}

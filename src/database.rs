use anyhow::Result;
use bitcoin::consensus::Encodable;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Database {
    pub conn: Connection,
}

impl Database {
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Database> {
        let conn = Connection::open(path)?;

        Ok(Database { conn })
    }

    pub fn connect_temporary_database() -> Result<Database> {
        let conn = Connection::open_in_memory()?;
        let db = Database { conn };
        db.reset()?;

        Ok(db)
    }

    pub fn reset(&self) -> Result<()> {
        self.conn.execute_batch(
            "DROP TABLE IF EXISTS outputs;
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
                DROP TABLE IF EXISTS \"transactions\";
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

    pub fn mark_output_as_spent(&self, tx_id: &str, output_id: u32) -> Result<()> {
        self.conn.execute(
            "UPDATE outputs SET is_spent = 1 WHERE tx_id = ?1 and output_id = ?2",
            params![tx_id, output_id],
        )?;
        Ok(())
    }

    pub fn check_if_output_is_spent(&self, tx_id: &str, output_id: u32) -> Result<bool> {
        let res = self.conn.query_row(
            "SELECT is_spent FROM outputs WHERE tx_id = ?1 and output_id = ?2",
            params![tx_id, output_id],
            |row| Ok(row.get::<_, u32>(0)? != 0),
        )?;
        Ok(res)
    }

    pub fn insert_transaction_unconditionally(&self, tx: &bitcoin::Transaction) -> Result<()> {
        let tx_id = tx.compute_txid().to_string();

        let num_inputs = tx.input.len();

        for i in 0..num_inputs {
            let input = tx.tx_in(i)?;
            self.mark_output_as_spent(
                &input.previous_output.txid.to_string(),
                input.previous_output.vout,
            )?;
        }

        let num_outputs = tx.output.len();

        let mut body = Vec::new();
        tx.consensus_encode(&mut body)?;

        self.conn.execute(
            "INSERT INTO \"transactions\" (tx_id, num_outputs, body) VALUES (?1, ?2, ?3)",
            params![tx_id, num_outputs, body],
        )?;

        for i in 0..num_outputs {
            let output = tx.tx_out(i)?;

            self.conn.execute(
                "INSERT INTO outputs (tx_id, output_id, value, script_pub_key, is_spent) VALUES (?1, ?2, ?3, ?4, 0)",
                params![tx_id, i, output.value.to_sat(), output.script_pubkey.to_bytes()]
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::database::Database;
    use crate::pushable;
    use bitcoin::absolute::LockTime;
    use bitcoin::script::scriptint_vec;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Script, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram,
    };
    use bitcoin_script::script;

    #[test]
    fn test_insert_unconditionally() {
        let db = Database::connect_temporary_database().unwrap();

        let witness_program = WitnessProgram::p2wsh(Script::from_bytes(
            &script! {
                { 1234 } OP_EQUAL
            }
            .to_bytes(),
        ));

        let output = TxOut {
            value: Amount::from_sat(1_000_000_000),
            script_pubkey: ScriptBuf::new_witness_program(&witness_program),
        };

        let tx = bitcoin::Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![output],
        };

        let tx_id = tx.compute_txid();

        db.insert_transaction_unconditionally(&tx).unwrap();

        assert_eq!(
            db.check_if_output_is_spent(&tx_id.to_string(), 0).unwrap(),
            false
        );

        let mut witness = Witness::new();
        witness.push([]);
        witness.push(scriptint_vec(1234));
        witness.push(script! { { 1234 } OP_EQUAL }.to_bytes());

        let input = TxIn {
            previous_output: OutPoint::new(tx_id, 0),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: witness,
        };

        let tx2 = bitcoin::Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![],
        };

        db.insert_transaction_unconditionally(&tx2).unwrap();

        assert_eq!(
            db.check_if_output_is_spent(&tx_id.to_string(), 0).unwrap(),
            true
        );
    }
}

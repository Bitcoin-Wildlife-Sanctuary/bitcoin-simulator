use crate::spending_requirements::{P2TRChecker, P2WSHChecker};
use anyhow::{Error, Result};
use bitcoin::consensus::Encodable;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
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

    pub fn get_prev_output(&self, tx_id: &str, output_id: u32) -> Result<TxOut> {
        let res = self.conn.query_row(
            "SELECT value, script_pub_key FROM outputs WHERE tx_id = ?1 and output_id = ?2",
            params![tx_id, output_id],
            |row| {
                Ok(TxOut {
                    value: Amount::from_sat(row.get::<_, u64>(0)?),
                    script_pubkey: ScriptBuf::from_bytes(row.get::<_, Vec<u8>>(1)?),
                })
            },
        )?;
        Ok(res)
    }

    pub fn insert_transaction_unconditionally(&self, tx: &Transaction) -> Result<()> {
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

    pub fn verify_transaction(&self, tx: &Transaction) -> Result<()> {
        let mut prev_outs = vec![];
        for input in tx.input.iter() {
            assert_eq!(
                input.script_sig.len(),
                0,
                "Bitcoin simulator only verifies inputs that support segregated witness."
            );

            let prev_out = self.get_prev_output(
                &input.previous_output.txid.to_string(),
                input.previous_output.vout,
            )?;
            prev_outs.push(prev_out);
        }

        for (input_idx, input) in tx.input.iter().enumerate() {
            if prev_outs[input_idx].script_pubkey.is_p2wsh() {
                P2WSHChecker::check(&tx, &prev_outs, input_idx, &input.witness)?;
            } else if prev_outs[input_idx].script_pubkey.is_p2tr() {
                P2TRChecker::check(&tx, &prev_outs, input_idx, &input.witness)?;
            }
        }

        let input_amount = prev_outs.iter().map(|x| x.value.to_sat()).sum::<u64>();
        let output_amount = tx.output.iter().map(|x| x.value.to_sat()).sum::<u64>();

        if input_amount < output_amount {
            return Err(Error::msg(
                "Input amount must be greater than the output amount.",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::database::Database;
    use crate::pushable;
    use bitcoin::absolute::LockTime;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::script::scriptint_vec;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Script, ScriptBuf, Sequence, TxIn, TxOut, Witness, WitnessProgram,
    };
    use bitcoin_script::script;
    use std::str::FromStr;

    #[test]
    fn test_p2wsh() {
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
            witness,
        };

        let tx2 = bitcoin::Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![],
        };

        assert!(db.verify_transaction(&tx2).is_ok());
        db.insert_transaction_unconditionally(&tx2).unwrap();

        assert_eq!(
            db.check_if_output_is_spent(&tx_id.to_string(), 0).unwrap(),
            true
        );
    }

    #[test]
    fn test_p2tr() {
        let db = Database::connect_temporary_database().unwrap();

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let internal_key = UntweakedPublicKey::from(
            bitcoin::secp256k1::PublicKey::from_str(
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            )
            .unwrap(),
        );

        let script = script! {
            { 1234 } OP_EQUAL
        };

        let taproot_builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        let witness_program =
            WitnessProgram::p2tr(&secp, internal_key, taproot_spend_info.merkle_root());

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

        let mut control_block_bytes = Vec::new();
        taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap()
            .encode(&mut control_block_bytes)
            .unwrap();

        let mut witness = Witness::new();
        witness.push(scriptint_vec(1234));
        witness.push(script! { { 1234 } OP_EQUAL }.to_bytes());
        witness.push(control_block_bytes);

        let input = TxIn {
            previous_output: OutPoint::new(tx_id, 0),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness,
        };

        let tx2 = bitcoin::Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![],
        };

        assert!(db.verify_transaction(&tx2).is_ok());
        db.insert_transaction_unconditionally(&tx2).unwrap();

        assert_eq!(
            db.check_if_output_is_spent(&tx_id.to_string(), 0).unwrap(),
            true
        );
    }
}

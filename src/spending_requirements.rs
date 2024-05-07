use anyhow::{Error, Result};
use bitcoin::key::TweakedPublicKey;
use bitcoin::taproot::ControlBlock;
use bitcoin::{secp256k1, Script, ScriptBuf, Witness, WitnessProgram, XOnlyPublicKey};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

pub struct P2WSHChecker;

impl P2WSHChecker {
    pub fn check(sig_pub_key: ScriptBuf, tx_template: TxTemplate, witness: Witness) -> Result<()> {
        let witness_version = sig_pub_key.as_bytes()[0];

        if witness_version != 0 {
            return Err(Error::msg("The ScriptPubKey is not for P2WSH."));
        }

        let mut witness = witness.to_vec();

        if witness.len() < 2 {
            return Err(Error::msg("The number of witness elements should be at least two (the empty placeholder and the script)."));
        }

        if !witness.remove(0).is_empty() {
            return Err(Error::msg(
                "The first witness element must be empty (aka, representing 0).",
            ));
        }

        let script = witness.pop().unwrap();

        let witness_program = WitnessProgram::p2wsh(&Script::from_bytes(&script));
        let sig_pub_key_expected = ScriptBuf::new_witness_program(&witness_program);

        if sig_pub_key != sig_pub_key_expected {
            return Err(Error::msg(
                "The script does not match the script public key.",
            ));
        }

        let mut exec = Exec::new(
            ExecCtx::SegwitV0,
            Options::default(),
            tx_template,
            ScriptBuf::from_bytes(script.to_vec()),
            witness,
        )
        .map_err(|_| Error::msg("The script cannot be executed."))?;
        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        if !res.success {
            return Err(Error::msg("The script execution is not successful."));
        }

        Ok(())
    }
}

pub struct P2TRChecker;

impl P2TRChecker {
    pub fn check(sig_pub_key: ScriptBuf, tx_template: TxTemplate, witness: Witness) -> Result<()> {
        let sig_pub_key_bytes = sig_pub_key.as_bytes();

        let witness_version = sig_pub_key_bytes[0];
        if witness_version != 0x51 {
            return Err(Error::msg("The ScriptPubKey is not for Taproot."));
        }

        if sig_pub_key_bytes.len() != 34 || sig_pub_key_bytes[1] != 0x20 {
            return Err(Error::msg(
                "The ScriptPubKey does not follow the Taproot format.",
            ));
        }

        let mut witness = witness.to_vec();
        let mut annex: Option<Vec<u8>> = None;

        if witness.len() >= 2 && witness[witness.len() - 1][0] == 0x50 {
            annex = Some(witness.pop().unwrap());
        }

        _ = annex;

        if witness.len() == 1 {
            return Err(Error::msg(
                "The key path spending of Taproot is not implemented.",
            ));
        }

        if witness.len() < 2 {
            return Err(Error::msg("The number of witness elements should be at least two (the script and the control block)."));
        }

        let secp = secp256k1::Secp256k1::new();

        let control_block = ControlBlock::decode(&witness.pop().unwrap())?;
        let script_buf = witness.pop().unwrap();
        let script = Script::from_bytes(&script_buf);

        let out_pk = XOnlyPublicKey::from_slice(&sig_pub_key_bytes[2..])?;
        let out_pk = TweakedPublicKey::dangerous_assume_tweaked(out_pk);

        let res = control_block.verify_taproot_commitment(&secp, out_pk.to_inner(), script);
        if !res {
            return Err(Error::msg(
                "The taproot commitment does not match the Taproot public key.",
            ));
        }

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            tx_template,
            ScriptBuf::from_bytes(script_buf),
            witness,
        )
        .map_err(|_| Error::msg("The script cannot be executed."))?;
        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        if !res.success {
            return Err(Error::msg("The script execution is not successful."));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::pushable;
    use crate::spending_requirements::{P2TRChecker, P2WSHChecker};
    use bitcoin::absolute::LockTime;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::script::scriptint_vec;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Script, ScriptBuf, Sequence, TapLeafHash, TxIn, TxOut, Witness,
        WitnessProgram,
    };
    use bitcoin_script::script;
    use bitcoin_scriptexec::TxTemplate;
    use std::str::FromStr;

    #[test]
    fn test_p2wsh() {
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
            output: vec![output.clone()],
        };

        let tx_id = tx.compute_txid();

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
            input: vec![input.clone()],
            output: vec![],
        };

        let res = P2WSHChecker::check(
            output.script_pubkey.clone(),
            TxTemplate {
                tx: tx2,
                prevouts: vec![output],
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
            input.witness,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_p2tr() {
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
            output: vec![output.clone()],
        };

        let tx_id = tx.compute_txid();

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
            input: vec![input.clone()],
            output: vec![],
        };

        let res = P2TRChecker::check(
            output.script_pubkey.clone(),
            TxTemplate {
                tx: tx2,
                prevouts: vec![output],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::from_script(&Script::from_bytes(script.as_bytes()), LeafVersion::TapScript), None)),
            },
            input.witness,
        );
        assert!(res.is_ok());
    }
}

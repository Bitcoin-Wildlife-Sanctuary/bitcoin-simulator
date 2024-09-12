use anyhow::{Error, Result};
use bitcoin::ecdsa::Signature;
use bitcoin::key::TweakedPublicKey;
use bitcoin::opcodes::all::OP_PUSHBYTES_20;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{ControlBlock, LeafVersion};
use bitcoin::{
    secp256k1, CompressedPublicKey, Script, ScriptBuf, TapLeafHash, Transaction, TxOut,
    WitnessProgram, XOnlyPublicKey,
};
use bitcoin_scriptexec::{Exec, ExecCtx, execute_script_with_witness_and_tx_template, Options, TxTemplate};

pub struct P2WPKHChecker;

impl P2WPKHChecker {
    pub fn check(tx: &Transaction, prevouts: &[TxOut], input_idx: usize) -> Result<()> {
        if prevouts[input_idx].script_pubkey.len() != 22 {
            return Err(Error::msg("The ScriptPubKey is not for P2WPKH."));
        }

        let witness_version = prevouts[input_idx].script_pubkey.as_bytes()[0];
        let witness = &tx.input[input_idx].witness;

        if witness.len() != 2 {
            return Err(Error::msg("The number of witness elements should be exactly two (the signature and the public key)."));
        }

        if witness_version != 0
            || prevouts[input_idx].script_pubkey.as_bytes()[1] != OP_PUSHBYTES_20.to_u8()
        {
            return Err(Error::msg("The ScriptPubKey is not for P2WPKH."));
        }

        let pk = CompressedPublicKey::from_slice(&witness[1])?;

        let wpkh = pk.wpubkey_hash();

        if !prevouts[input_idx].script_pubkey.as_bytes()[2..22].eq(AsRef::<[u8]>::as_ref(&wpkh)) {
            return Err(Error::msg(
                "The script does not match the script public key.",
            ));
        }

        let sig = Signature::from_slice(&witness[0])?;

        let mut sighashcache = SighashCache::new(tx.clone());
        let h = sighashcache.p2wpkh_signature_hash(
            input_idx,
            &ScriptBuf::new_p2wpkh(&wpkh),
            prevouts[input_idx].value,
            sig.sighash_type,
        )?;

        let msg = Message::from(h);
        let secp = secp256k1::Secp256k1::verification_only();
        pk.verify(&secp, &msg, &sig)?;

        Ok(())
    }
}

pub struct P2WSHChecker;

impl P2WSHChecker {
    pub fn check(tx: &Transaction, prevouts: &[TxOut], input_idx: usize) -> Result<()> {
        let witness_version = prevouts[input_idx].script_pubkey.as_bytes()[0];

        if witness_version != 0 {
            return Err(Error::msg("The ScriptPubKey is not for P2WSH."));
        }

        let mut witness = tx.input[input_idx].witness.to_vec();

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

        if *prevouts[input_idx].script_pubkey != sig_pub_key_expected {
            return Err(Error::msg(
                "The script does not match the script public key.",
            ));
        }

        let tx_template = TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.to_vec(),
            input_idx,
            taproot_annex_scriptleaf: None,
        };

        let mut exec = Exec::new(
            ExecCtx::SegwitV0,
            Options::default(),
            tx_template,
            ScriptBuf::from_bytes(script.to_vec()),
            witness,
        )
        .map_err(|e| Error::msg(format!("The script cannot be executed: {:?}", e)))?;
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
    pub fn check(tx: &Transaction, prevouts: &[TxOut], input_idx: usize) -> Result<()> {
        let sig_pub_key_bytes = prevouts[input_idx].script_pubkey.as_bytes();

        let witness_version = sig_pub_key_bytes[0];
        if witness_version != 0x51 {
            return Err(Error::msg("The ScriptPubKey is not for Taproot."));
        }

        if sig_pub_key_bytes.len() != 34 || sig_pub_key_bytes[1] != 0x20 {
            return Err(Error::msg(
                "The ScriptPubKey does not follow the Taproot format.",
            ));
        }

        let mut witness = tx.input[input_idx].witness.to_vec();
        let mut annex: Option<Vec<u8>> = None;

        if witness.len() >= 2 && witness[witness.len() - 1][0] == 0x50 {
            annex = Some(witness.pop().unwrap());
        }

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

        let tx_template = TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.to_vec(),
            input_idx,
            taproot_annex_scriptleaf: Some((
                TapLeafHash::from_script(script, LeafVersion::TapScript),
                annex,
            )),
        };

        let exec_result = execute_script_with_witness_and_tx_template(
            ScriptBuf::from_bytes(script_buf),
            tx_template,
            witness
        );
        if !exec_result.success {
            println!("{:?}", exec_result.stats);
            return Err(Error::msg("The script execution is not successful."));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::pushable;
    use crate::spending_requirements::{P2TRChecker, P2WPKHChecker, P2WSHChecker};
    use bitcoin::absolute::LockTime;
    use bitcoin::ecdsa::Signature;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, EcdsaSighashType, OutPoint, Script, ScriptBuf, Sequence, TxIn, TxOut, Witness,
        WitnessProgram,
    };
    use bitcoin_script::script;
    use bitcoin_scriptexec::utils::scriptint_vec;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn test_p2wpkh() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let secp = Secp256k1::new();

        let sk = SecretKey::new(&mut prng);
        let pk = sk.public_key(&secp);

        let wpkh = bitcoin::PublicKey::new(pk).wpubkey_hash().unwrap();

        let output = TxOut {
            value: Amount::from_sat(1_000_000_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
        };

        let tx = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![output.clone()],
        };

        let tx_id = tx.compute_txid();

        let input = TxIn {
            previous_output: OutPoint {
                txid: tx_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::default(),
            witness: Witness::default(),
        };

        let mut tx2 = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![input.clone()],
            output: vec![],
        };

        let sighash_type = EcdsaSighashType::All;
        let mut sighashcache = SighashCache::new(tx2.clone());
        let h = sighashcache
            .p2wpkh_signature_hash(0, &output.script_pubkey, output.value, sighash_type)
            .unwrap();

        let msg = Message::from(h);
        let signature = Signature {
            signature: secp.sign_ecdsa(&msg, &sk),
            sighash_type,
        };

        tx2.input[0].witness = Witness::p2wpkh(&signature, &pk);

        let res = P2WPKHChecker::check(&tx2, &[output], 0);
        assert!(res.is_ok());
    }

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
            version: Version::ONE,
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
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![input.clone()],
            output: vec![],
        };

        let res = P2WSHChecker::check(&tx2, &[output], 0);
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
            version: Version::ONE,
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
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![input.clone()],
            output: vec![],
        };

        let res = P2TRChecker::check(&tx2, &[output], 0);
        assert!(res.is_ok());
    }
}

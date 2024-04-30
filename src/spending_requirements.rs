use anyhow::{Error, Result};
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::ControlBlock;
use bitcoin::{
    secp256k1, Script, ScriptBuf, Witness, WitnessProgram, WitnessVersion, XOnlyPublicKey,
};
use bitcoin_script::script;
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
        )?;
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
        if witness_version != 1 {
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
        let script = Script::from_bytes(&witness.pop().unwrap());

        let out_pk = XOnlyPublicKey::from_slice(sig_pub_key_bytes)?;
        let out_pk = TweakedPublicKey::dangerous_assume_tweaked(out_pk);

        let res = control_block.verify_taproot_commitment(&secp, out_pk.to_inner(), script)?;
        if !res {
            return Err(Error::msg(
                "The taproot commitment does not match the Taproot public key.",
            ));
        }

        Ok(())
    }
}

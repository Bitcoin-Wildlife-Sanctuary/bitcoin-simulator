use bitcoin::opcodes::all::{OP_PUSHBYTES_0, OP_PUSHBYTES_1, OP_PUSHBYTES_3, OP_PUSHBYTES_4};
use bitcoin::{ScriptBuf, TapSighashType};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin_script::script;

pub struct SchnorrTrickGadget;

impl SchnorrTrickGadget {
    pub fn step1_add_epoch() -> ScriptBuf {
        script! {
            OP_PUSHBYTES_1 OP_PUSHBYTES_0
        }
    }

    pub fn step_2_add_hash_type(hash_type: TapSighashType) -> ScriptBuf {
        match hash_type {
            TapSighashType::Default => {
                script! {
                    OP_PUSHBYTES_1 OP_PUSHBYTES_0
                }
            }
            TapSighashType::All => {
                script! {
                    OP_PUSHBYTES_1 OP_PUSHBYTES_1
                }
            }
            TapSighashType::None => {
                script! {
                    OP_PUSHBYTES_1 OP_PUSHBYTES_2
                }
            }
            TapSighashType::Single => {
                script! {
                    OP_PUSHBYTES_1 OP_PUSHBYTES_3
                }
            }
            TapSighashType::AllPlusAnyoneCanPay => {
                script! {
                    OP_PUSHBYTES_1 OP_RIGHT
                }
            }
            TapSighashType::NonePlusAnyoneCanPay => {
                script! {
                    OP_PUSHBYTES_1 OP_SIZE
                }
            }
            TapSighashType::SinglePlusAnyoneCanPay => {
                script! {
                    OP_PUSHBYTES_1 OP_INVERT
                }
            }
        }
    }

    pub fn step_3_add_nversion(version: Version) -> ScriptBuf {
        assert!(version == Version::ONE || version == Version::TWO);

        if version == Version::ONE {
            script! {
                OP_PUSHBYTES_4 OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
            }
        } else {
            script! {
                OP_PUSHBYTES_4 OP_PUSHBYTES_2 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
            }
        }
    }

    pub fn step_4_add_nlocktime(lock_time: LockTime) -> ScriptBuf {
        let v = lock_time.to_consensus_u32();
        ScriptBuf::from_bytes(vec![OP_PUSHBYTES_4.to_u8(), (v & 0xff) as u8, ]);
    }
}
extern crate secp256k1;
extern crate hex;
extern crate crypto;

use std::iter::repeat;
use std::str::FromStr;
use secp256k1::{Secp256k1, Message};
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

pub fn recover_user_pubaddress(sig:&str, hash:&str) -> Result<String,String> {
    if sig.len() != 130 {
        Err("signature length err".to_string())
    }else {
        let recover_param: i32 = FromStr::from_str(&sig[(sig.len()-2)..]).unwrap();
        let sig_decoded = hex::decode(&sig[..128]).expect("Decoding failed");

        let hashbytes = hex::decode(hash).expect("Decoding failed");
	    let msghash = Message::from_slice(&hashbytes).ok().unwrap();
        let recid = secp256k1::recovery::RecoveryId::from_i32(recover_param).ok().unwrap();
	    let recoverablesig = secp256k1::recovery::RecoverableSignature::from_compact(&sig_decoded, recid).ok().unwrap();

	    let secp = Secp256k1::new();
	    let pubkey = secp.recover(&msghash, &recoverablesig);
        match pubkey {
                        Ok(_pubkey) => {
							let pubkey_bytes = _pubkey.serialize_uncompressed();
                    		let mut hasher = Sha3::keccak256();
                    		hasher.input(&pubkey_bytes[1..]);
                            let mut buf: Vec<u8> = repeat(0).take(32).collect();
                    		hasher.result(&mut buf);
                            Ok(hex::encode(&buf[32-20..]).to_string())
                        },
                        Err(e) => {
                            Err(e.to_string())
                        }
        }




    }
}

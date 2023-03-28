use bincode;
use blsttc::{Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PK_SIZE};
use rand;
use std::{collections::BTreeMap, io::Read};
use taubyte_sdk::{
    i2mv::memview::{Closer, ReadSeekCloser},
    utils::codec::bytes_slice,
};

/// Encrypts a message using a public key and thread rng.
/// Returns the id of the Memory View with the encrypted data. 
///
/// 
/// # Arguments 
/// 
/// * `pk_id` - A UInt32 id referring to the Memory View with the stored public key.
/// 
/// * `msg_id` - A UInt32 id referring to the Memory View with the stored message to be encrypted.
#[no_mangle]
pub fn encrypt(pk_id: u32, msg_id: u32) -> u32 {
    let mut pk_mv = ReadSeekCloser::open(pk_id).unwrap_or_else(|err| {
        panic!("opening public key memory view failed with: {}", err);
    });

    let mut pk_buffer = [0; PK_SIZE];
    let _ = pk_mv.read(&mut pk_buffer).unwrap_or_else(|err| {
        panic!("reading public key memory view failed with: {}", err);
    });

    let pk = PublicKey::from_bytes(pk_buffer).unwrap_or_else(|err| {
        panic!(
            "creating public key from public key bytes failed with: {}",
            err
        );
    });

    let mut msg_mv = ReadSeekCloser::open(msg_id).unwrap_or_else(|err| {
        panic!("opening message memory view failed with: {}", err);
    });

    let mut msg_buffer: Vec<u8> = Vec::new();

    let _ = msg_mv.read_to_end(&mut msg_buffer).unwrap_or_else(|err| {
        panic!("reading message memory view failed with: {}", err);
    });

    let mut rng = rand::thread_rng();
    let ct = pk.encrypt_with_rng(&mut rng, msg_buffer);
    let bincode_ct_vec = bincode::serialize(&ct).unwrap_or_else(|err| {
        panic!("serializing cipher text failed with: {}", err);
    });

    let beb = reverse_bytes(bincode_ct_vec);

    Closer::new(&beb, true).unwrap().id
}

/// Decrypts the ciphered text using the recombined decryption shares,
/// and returns the id of the Memory View with the decrypted data.
/// 
/// # Arguments 
/// 
/// * `public_key_set_id` - A UInt32 id referring to the Memory View with the stored public key set. 
/// 
/// * `shares_id` - A UInt32 id referring to the Memory View with the stored 
#[no_mangle]
pub fn decrypt(public_key_set_id:u32, shares_id: u32, cipher_text_id: u32) -> u32{
    let mut dshares = BTreeMap::new();

    let mut shares_mv = ReadSeekCloser::open(shares_id).unwrap_or_else(|err| {
        panic!("opening shares failed with: {}", err);
    });

    let mut shares_encoded:Vec<u8> =Vec::new();
    let _ = shares_mv.read_to_end(&mut shares_encoded);
    let shares_decoded = bytes_slice::to(shares_encoded);
    for (idx, share) in shares_decoded.iter().enumerate() {
        let bincode_dshare_bytes = reverse_bytes(share.to_vec());
        let dshare: DecryptionShare = bincode::deserialize(&bincode_dshare_bytes).unwrap_or_else(|err| {
            panic!("deserializing dshare bytes failed with: {}", err);
        });

        dshares.insert(idx, dshare);
    }

    let mut public_key_set_mv = ReadSeekCloser::open(public_key_set_id).unwrap_or_else(|err| {
        panic!("opening public key memory view failed with: {}", err);
    });

    let mut public_key_set_buffer:Vec<u8> = Vec::new();

    let _ = public_key_set_mv.read_to_end(&mut public_key_set_buffer).unwrap_or_else(|err| {
        panic!("reading public key memory view failed with: {}", err);
    });


    let bincode_pkset_bytes = reverse_bytes(public_key_set_buffer);

    let public_key_set: PublicKeySet = bincode::deserialize(&bincode_pkset_bytes).unwrap_or_else(|err| {
        panic!("deserializing public key set failed with: {} sz: {}", err,bincode_pkset_bytes.len());
    });

    let mut cipher_text_mv = ReadSeekCloser::open(cipher_text_id).unwrap_or_else(|err| {
        panic!("opening cipher text failed with: {}", err);
    });

    let mut cipher_text:Vec<u8> = Vec::new();
    let _ = cipher_text_mv.read_to_end(&mut cipher_text);
    let bincode_ct_vec = reverse_bytes(cipher_text);

    let ct: Ciphertext = bincode::deserialize(&bincode_ct_vec).unwrap_or_else(|err| {
        panic!("deserializing cipher text failed with: {}", err);
    });

    let msg = public_key_set.decrypt(&dshares, &ct).unwrap_or_else(|err| {
        panic!("decrypting shares failed with: {}", err);
    });

    Closer::new(&msg, true).unwrap().id
}

fn reverse_bytes(buffer: Vec<u8>) -> Vec<u8>{
    let mut buffer0 = buffer.clone();
    buffer0.reverse();
    buffer0
}
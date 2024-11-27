extern crate libc;

use std::slice;
use sha2::{Sha512, Digest};
use salsa20::{Salsa20, XSalsa20};
// Import relevant traits
use salsa20::cipher::{KeyIvInit, StreamCipher};
use poly1305::{
    universal_hash::KeyInit, Poly1305,
};
use x25519_dalek::x25519;

#[no_mangle]
pub extern "C" fn x25519_rust(output: *mut u8, public: *mut u8, secret: *mut u8) {
    // build a Rust array from array & length
    let x25519_len: usize = 32;
    let rust_public: &mut [u8] = unsafe { slice::from_raw_parts_mut(public, x25519_len as usize) };
    let rust_secret: &mut [u8] = unsafe { slice::from_raw_parts_mut(secret, x25519_len as usize) };
    let rust_output: &mut [u8] = unsafe { slice::from_raw_parts_mut(output, x25519_len as usize) };
    
    let mut secret_key : [u8;32] = [0; 32];
    let mut public_key : [u8;32] = [0; 32];

    let mut i = 0;
    for element in rust_secret.iter_mut() {
        secret_key[i] = *element;
        i=i+1;
    }

    i = 0;
    for element in rust_public.iter_mut() {
        public_key[i] = *element;
        i=i+1;
    }

    let shared = x25519(public_key,secret_key);

    i = 0;
    for element in rust_output.iter_mut() {
        *element = shared[i];
        i=i+1;
    }
}

#[no_mangle]
pub extern "C" fn poly1305_rust(mac: *mut u8, msg: *mut u8, length: usize, key: *mut u8) {
    // build a Rust array from array & length
    let poly1305_len: usize = 32;
    let poly1305_mac_len: usize = 16;
    let rust_msg: &mut [u8] = unsafe { slice::from_raw_parts_mut(msg, length as usize) };
    let rust_key: &mut [u8] = unsafe { slice::from_raw_parts_mut(key, poly1305_len as usize) };
    let rust_mac: &mut [u8] = unsafe { slice::from_raw_parts_mut(mac, poly1305_mac_len as usize) };

    let mut key : [u8;32] = [0; 32];
    let mut i = 0;
    for element in rust_key.iter_mut() {
        key[i] = *element;
        i=i+1;
    }
    let result = Poly1305::new(key.as_ref().into()).compute_unpadded(rust_msg);
    i=0;
    for element in rust_mac.iter_mut() {
        *element = result[i];
        i=i+1;
    }
}

#[no_mangle]
pub extern "C" fn sha512_rust(output: *mut u8, input: *mut u8, length: usize) {
    // build a Rust array from array & length
    let digest_len: usize = 64;
    let rust_input: &mut [u8] = unsafe { slice::from_raw_parts_mut(input, length as usize) };
    let rust_output: &mut [u8] = unsafe { slice::from_raw_parts_mut(output, digest_len as usize) };
    
    let mut hasher = Sha512::new();
    hasher.update(rust_input);
    let result = hasher.finalize();

    let mut i: usize = 0;
    for element in rust_output.iter_mut() {
        *element = result[i];
        i=i+1;
    }
}

#[no_mangle]
pub extern "C" fn salsa20_rust(message: *mut u8, length: usize, key: *mut u8, nonce: *mut u8) {
    const SALSA20_KEY_LEN: usize = 32;
    const SALSA20_NONCE_LEN: usize = 8;
    let rust_key: &mut [u8] = unsafe { slice::from_raw_parts_mut(key, SALSA20_KEY_LEN as usize) };
    let rust_nonce: &mut [u8] = unsafe { slice::from_raw_parts_mut(nonce, SALSA20_NONCE_LEN as usize) };
    let rust_message: &mut [u8] = unsafe { slice::from_raw_parts_mut(message, length as usize) };    
    let mut key : [u8;32] = [0; 32];
    let mut i = 0;
    for element in rust_key.iter_mut() {
        key[i] = *element;
        i=i+1;
    }
    let mut nonce : [u8;8] = [0; 8];
    i = 0;
    for element in rust_nonce.iter_mut() {
        nonce[i] = *element;
        i=i+1;
    }
    // Key and IV must be references to the `GenericArray` type.
    // Here we use the `Into` trait to convert arrays into it.
    let mut cipher = Salsa20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(rust_message);
}

#[no_mangle]
pub extern "C" fn xsalsa20_rust(message: *mut u8, length: usize, key: *mut u8, nonce: *mut u8) {
    const XSALSA20_KEY_LEN: usize = 32;
    const XSALSA20_NONCE_LEN: usize = 24;
    let rust_key: &mut [u8] = unsafe { slice::from_raw_parts_mut(key, XSALSA20_KEY_LEN as usize) };
    let rust_nonce: &mut [u8] = unsafe { slice::from_raw_parts_mut(nonce, XSALSA20_NONCE_LEN as usize) };
    let rust_message: &mut [u8] = unsafe { slice::from_raw_parts_mut(message, length as usize) };    
    let mut key : [u8;32] = [0; 32];
    let mut i = 0;
    for element in rust_key.iter_mut() {
        key[i] = *element;
        i=i+1;
    }
    let mut nonce : [u8;24] = [0; 24];
    i = 0;
    for element in rust_nonce.iter_mut() {
        nonce[i] = *element;
        i=i+1;
    }
    // Key and IV must be references to the `GenericArray` type.
    // Here we use the `Into` trait to convert arrays into it.
    let mut cipher = XSalsa20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(rust_message);
}

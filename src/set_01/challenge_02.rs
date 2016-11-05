// Fixed XOR
// Write a function that takes two equal-length buffers and produces their XOR combination.
//
// If your function works properly, then when you feed it the string:
//  1c0111001f010100061a024b53535009181c
// ... after hex decoding, and when XOR'd against:
//  686974207468652062756c6c277320657965
// ... should produce:
//  746865206b696420646f6e277420706c6179

use data_encoding::hex;

pub fn fixed_xor (a: &str, b: &str) -> String {
    if a.len() != b.len() {
        panic!();
    }

    let a = hex::decode(a.to_string().to_uppercase().as_bytes()).unwrap();
    let b = hex::decode(b.to_string().to_uppercase().as_bytes()).unwrap();
    let mut xored = Vec::with_capacity(a.len());
    for n in 0..a.len() {
        xored.push(a[n] ^ b[n]);
    }
    hex::encode(&xored)
}

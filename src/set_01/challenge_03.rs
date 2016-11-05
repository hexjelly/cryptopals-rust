// Single-byte XOR cipher
// The hex encoded string:
//     1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// ... has been XOR'd against a single character. Find the key, decrypt the message.
//
// You can do this by hand. But don't: write code to do it for you.
//
// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

use data_encoding::hex;
use std::cmp::Ordering;
use std::f32::MAX as f32_max;

const LETTER_FREQUENCY: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074];

#[derive(Debug, PartialEq, Clone)]
pub struct Chi2Result<'a> {
    pub text: String,
    pub key: u8,
    pub chi2: f32,
    pub hex: &'a str
}


pub fn chi2 (text: String, key: u8, hex: &str) -> Chi2Result {
    let mut count = [0;26];
    let mut ignored = 0;

    for byte in text.as_bytes() {
        if *byte >= 65_u8 && *byte <= 90_u8 { count[(byte - 65) as usize] += 1 }
        else if *byte >= 97_u8 && *byte <= 122_u8 { count[(byte - 97) as usize] += 1 }
        else if *byte >= 32_u8 && *byte <= 126_u8 { ignored += 1 }
        else if *byte == 9_u8 || *byte == 10_u8 || *byte == 13_u8 { ignored += 1 }
        else { return Chi2Result { text: text.clone(), key: key, chi2: f32_max, hex: hex }; }
    }

    let length = text.len() + ignored * 5;
    let mut result = Chi2Result { text: text, key: key, chi2: 0_f32, hex: hex };

    for n in 0..26 {
        let found = count[n];
        let expected = length as f32 * LETTER_FREQUENCY[n];
        let diff = found as f32 - expected;
        result.chi2 += diff * diff / expected;
    }

    result
}

pub fn single_byte_xor_cipher (hex: &str) -> Vec<Chi2Result> {
    let mut analysis: Vec<Chi2Result> = vec![];
    let hex_decoded = hex::decode(hex.to_string().to_uppercase().as_bytes()).unwrap();
    for n in 32..127 {
    // for n in (65..91).chain(97..123) {
        let mut test = hex_decoded.clone();
        for b in test.as_mut_slice() {
            *b ^= n;
        }
        let string = String::from_utf8(test);
        if string.is_ok() { analysis.push(chi2(string.unwrap(), n as u8, hex)); }
    }
    analysis.sort_by(|a, b| a.chi2.partial_cmp(&b.chi2).unwrap_or(Ordering::Equal));
    analysis
}

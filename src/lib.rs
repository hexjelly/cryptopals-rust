extern crate data_encoding;

use data_encoding::hex;
use data_encoding::base64;
use std::cmp::Ordering;

pub fn hex_to_base64 (input_hex: &str) -> String {
    let hex_decoded = hex::decode(input_hex.to_string().to_uppercase().as_bytes()).unwrap();
    base64::encode(&hex_decoded)
}

pub fn fixed_xor (a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len() != b.len() {
        return Err("Input not equal length.".to_string());
    }

    let mut xored = Vec::with_capacity(a.len());
    for (a, b) in a.iter().zip(b.iter()) {
        xored.push(a ^ b);
    }

    Ok(xored)
}

const LETTER_FREQUENCY: [f32; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.20987];

#[derive(Debug, PartialEq, Clone)]
pub struct Chi2Result {
    pub text: String,
    pub key: u8,
    pub chi2: f32,
    pub data: Vec<u8>
}


pub fn chi2 (text: &str) -> f32 {
    let mut count = [0;27];
    let mut ignored = 0;

    for byte in text.as_bytes() {
        if *byte >= 65_u8 && *byte <= 90_u8 { count[(byte - 65) as usize] += 1 }
        else if *byte >= 97_u8 && *byte <= 122_u8 { count[(byte - 97) as usize] += 1 }
        else if *byte == 32 { count[26] += 1 }
        else if *byte >= 33_u8 && *byte <= 126_u8 { ignored += 1 }
        else if *byte == 9_u8 || *byte == 10_u8 || *byte == 13_u8 { ignored += 1 }
        else { ignored += 10 }
    }

    let length = text.len() + ignored;
    let mut result = 0.;

    for n in 0..27 {
        let found = count[n];
        let expected = length as f32 * LETTER_FREQUENCY[n];
        let diff = found as f32 - expected;
        result += diff * diff / expected;
    }

    result
}

pub fn find_single_byte_xor_cipher (input: &[u8]) -> Option<Chi2Result> {
    let mut analysis = Vec::new();
    for n in 0..256 as usize {
        let mut tmp = input.to_vec();
        for b in &mut tmp {
            *b ^= n as u8;
        }
        let string = String::from_utf8(tmp);
        if string.is_ok() {
            let string = string.unwrap();
            analysis.push(Chi2Result {
                text: string.clone(),
                key: n as u8,
                chi2: chi2(&string),
                data: input.to_vec()
            });
        }
    }
    if analysis.is_empty() { return None; }
    analysis.sort_by(|a, b| a.chi2.partial_cmp(&b.chi2).unwrap_or(Ordering::Equal));

    Some(analysis.remove(0))
}

pub fn repeating_key_xor (data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = vec!();
    let mut key_iter = key.iter().cycle();
    for b in data {
        result.push(b ^ *key_iter.next().unwrap());
    }
    result
}

pub fn hamming_distance (a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() { return None; }
    let mut result = 0;
    for (a, b) in a.iter().zip(b.iter()) {
        let mut val = a ^ b;
        while val != 0 {
            result += 1;
            val &= val - 1;
        }
    }
    Some(result)
}

pub fn break_repeating_key_xor (cipher: &[u8], min_key_len: usize, max_key_len: usize) -> Vec<u8> {
    let mut tmp = vec!();
    for n in min_key_len..max_key_len+1 {
        let distance = (n, hamming_distance(&cipher[0..n], &cipher[n * 4..n * 5]).unwrap() as f32 / n as f32);
        tmp.push(distance);
    }

    tmp.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    let key_length = tmp[0].0;
    let mut blocks = vec!();
    for _ in 0..key_length {
        blocks.push(vec!());
    }
    for (n, byte) in cipher.iter().enumerate()  {
        blocks[n % key_length].push(*byte);
    }

    let mut result = vec!();
    for block in blocks {
        result.push(find_single_byte_xor_cipher(&block).unwrap().key);
    }

    result
}

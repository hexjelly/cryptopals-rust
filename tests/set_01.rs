extern crate cryptopals;
extern crate data_encoding;

mod test_data;

use cryptopals::*;
use data_encoding::base64;
use data_encoding::hex;
use std::cmp::Ordering;
use test_data::{ CHALLENGE_03_CONTENT, CHALLENGE_06_CONTENT };

// Convert hex to base64
// The string:
//  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// Should produce:
//  SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
#[test]
fn hex_to_base64_returns_correct_base64_value () {
    let test = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    assert_eq!(test, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

// Fixed XOR
// Write a function that takes two equal-length buffers and produces their XOR combination.
//
// If your function works properly, then when you feed it the string:
//  1c0111001f010100061a024b53535009181c
// ... after hex decoding, and when XOR'd against:
//  686974207468652062756c6c277320657965
// ... should produce:
//  746865206b696420646f6e277420706c6179
#[test]
fn fixed_xor_returns_correct_hex_value () {
    let hex_1 = hex::decode("1c0111001f010100061a024b53535009181c".to_string().to_uppercase().as_bytes()).unwrap();
    let hex_2 = hex::decode("686974207468652062756c6c277320657965".to_string().to_uppercase().as_bytes()).unwrap();
    let result = fixed_xor(&hex_1, &hex_2).unwrap();
    let tmp = hex::encode(&result);
    assert_eq!(tmp, "746865206b696420646f6e277420706c6179".to_string().to_uppercase());
}

#[test]
#[should_panic]
fn fixed_xor_panics_on_uneven_input () {
    fixed_xor(&[32, 56, 95], &[89, 42]).unwrap();
}

// Single-byte XOR cipher
// The hex encoded string:
//     1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// ... has been XOR'd against a single character. Find the key, decrypt the message.
//
// You can do this by hand. But don't: write code to do it for you.
//
// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
#[test]
fn find_single_byte_xor_cipher_returns_correct_value () {
    if let Some(chi2_list) = find_single_byte_xor_cipher(&hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string().to_uppercase().as_bytes()).unwrap()) {
        assert_eq!(chi2_list.text, "Cooking MC\'s like a pound of bacon");
        assert_eq!(chi2_list.key, 88);
    } else {
        assert!(false);
    }
}

// Detect single-character XOR
// One of the 60-character strings in this file has been encrypted by single-character XOR.
//
// Find it.
//
// (Your code from #3 should help.)
fn detect_single_char_xor (hashes: &[&'static str]) -> Option<Chi2Result> {
    let mut result: Vec<Chi2Result> = vec!();
    for hash in hashes {
        if let Some(best_match) = find_single_byte_xor_cipher(&hex::decode(hash.to_string().to_uppercase().as_bytes()).unwrap()) {
            result.push(best_match);
        }
    }
    if result.is_empty() { return None; }
    result.sort_by(|a, b| a.chi2.partial_cmp(&b.chi2).unwrap_or(Ordering::Equal));

    Some(result.remove(0))
}

#[test]
fn detect_single_char_xor_returns_correct_value () {
    if let Some(chi2_list) = detect_single_char_xor(&CHALLENGE_03_CONTENT) {
        assert_eq!(chi2_list.text, "Now that the party is jumping\n");
        assert_eq!(chi2_list.data, hex::decode("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".to_string().to_uppercase().as_bytes()).unwrap());
        assert_eq!(chi2_list.key, 53);
    } else {
        assert!(false);
    }
}

// Implement repeating-key XOR
// Here is the opening stanza of an important work of the English language:
//  Burning 'em, if you ain't quick and nimble
//  I go crazy when I hear a cymbal
// Encrypt it, under the key "ICE", using repeating-key XOR.
//
// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
//
// It should come out to:
//  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
//  a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
#[test]
fn repeating_key_xor_returns_correct_value () {
    let test = repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b"ICE");
    assert_eq!(hex::encode(&test), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".to_string().to_uppercase());
}

// Break repeating-key XOR
// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
//
// Decrypt it.
// Here's how:
//
// Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
// Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
//  this is a test
// and
//  wokka wokka!!!
// is 37. Make sure your code agrees before you proceed.
// For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
// The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
// Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
// Solve each block as if it was single-character XOR. You already have code to do this.
// For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
#[test]
fn hamming_distance_returns_correct_value () {
    let result = hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap();
    assert_eq!(result, 37);
}

#[test]
fn break_repeating_key_xor_returns_correct_value () {
    let data = base64::decode(CHALLENGE_06_CONTENT.as_bytes()).unwrap();
    let key = break_repeating_key_xor(&data, 2, 40);
    let deciphered = repeating_key_xor(&data, &key);
    assert_eq!(key, b"Terminator X: Bring the noise");
    assert_eq!(deciphered[0..35], b"I'm back and I'm ringin' the bell \n"[..]);
}

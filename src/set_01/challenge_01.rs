// Convert hex to base64
// The string:
//  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// Should produce:
//  SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

use data_encoding::hex;
use data_encoding::base64;

pub fn hex_to_base64 (input_hex: &str) -> String {
    let hex_decoded = hex::decode(input_hex.to_string().to_uppercase().as_bytes()).unwrap();
    base64::encode(&hex_decoded)
}

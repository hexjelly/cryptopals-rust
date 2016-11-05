extern crate data_encoding;

use data_encoding::hex;
use data_encoding::base64;

fn main () {
    let from_hex = hex::decode(b"49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D").unwrap();
    let base64 = base64::encode(&from_hex);
    println!("hex_decoded: {:?}\nbase64_encoded: {:?}", from_hex, base64);
    assert_eq!(base64, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

use data_encoding::hex;
use data_encoding::base64;

// Convert hex to base64
pub fn hex_to_base64 (input_hex: &str) -> String {
    let hex_decoded = hex::decode(input_hex.to_string().to_uppercase().as_bytes()).unwrap();
    base64::encode(&hex_decoded)
}

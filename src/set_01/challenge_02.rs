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

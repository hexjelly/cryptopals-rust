extern crate cryptopals;

#[cfg(test)]
mod tests {
    use cryptopals::set_01::{ challenge_01, challenge_02 };

    #[test]
    fn hex_to_base64 () {
        let test = challenge_01::hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(test, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    #[test]
    fn fixed_xor () {
        let test = challenge_02::fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965");
        assert_eq!(test, "746865206b696420646f6e277420706c6179".to_string().to_uppercase());
    }

    #[test]
    #[should_panic]
    fn fixed_xor_uneven () {
        let _test = challenge_02::fixed_xor("1c1c", "efa0c1");
    }

    #[test]
    fn single_byte_xor_cipher () {
        let key = challenge_03::single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assert_eq!();
    }
}

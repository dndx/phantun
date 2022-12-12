use fake_tcp::packet::MAX_PACKET_LEN;
use std::convert::From;
use std::time::Duration;

pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum Encryption {
    Xor(Vec<u8>),
}

impl From<String> for Encryption {
    fn from(input: String) -> Self {
        Self::from(input.as_str())
    }
}

impl From<&String> for Encryption {
    fn from(input: &String) -> Self {
        Self::from(input.as_str())
    }
}

impl From<&str> for Encryption {
    fn from(input: &str) -> Self {
        let input = input.to_lowercase();
        let input: Vec<&str> = input.splitn(2, ':').collect();
        match input[0] {
            "xor" => {
                if input.len() < 2 {
                    panic!("xor key should be provided");
                } else {
                    Self::Xor(
                        input[1]
                            .repeat((MAX_PACKET_LEN as f32 / input[1].len() as f32).ceil() as usize)
                            [..MAX_PACKET_LEN]
                            .into(),
                    )
                }
            }
            _ => {
                panic!("input[0] encryption is not supported.");
            }
        }
    }
}

impl Encryption {
    // in-place encryption
    pub fn encrypt(&self, input: &mut [u8]) {
        match self {
            Self::Xor(ref key) => {
                let len = input.len();
                let input = &mut input[..len];
                let key = &key[..len];
                for i in 0..len {
                    input[i] ^= key[i];
                }
            }
        }
    }

    // in-place decryption
    pub fn decrypt(&self, input: &mut [u8]) {
        match self {
            Self::Xor(ref key) => {
                let len = input.len();
                let input = &mut input[..len];
                let key = &key[..len];
                for i in 0..len {
                    input[i] ^= key[i];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Encryption;
    use rand::Rng;

    fn xor_encryption_test(model: &str) {
        let enc = Encryption::from(model);
        let origin: Vec<u8> = rand::thread_rng()
            .sample_iter(&rand::distributions::Standard)
            .take(1500)
            .collect();
        let mut test = origin.clone();
        enc.encrypt(&mut test);
        let mut is_equal = true;
        for (i, _) in origin.iter().enumerate() {
            if origin[i] != test[i] {
                is_equal = false;
            }
        }
        assert!(!is_equal);
        enc.decrypt(&mut test);
        for (i, _) in origin.iter().enumerate() {
            assert_eq!(origin[i], test[i]);
        }
    }

    #[test]
    #[should_panic]
    fn xor_encryption_with_no_key() {
        xor_encryption_test("xor");
    }

    #[test]
    fn xor_encryption_with_min_key() {
        let key: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(1)
            .map(char::from)
            .collect();
        xor_encryption_test(format!("xor:{key}").as_str());
    }

    #[test]
    fn xor_encryption_with_max_key() {
        let key: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(1500)
            .map(char::from)
            .collect();
        xor_encryption_test(format!("xor:{key}").as_str());
    }

    #[test]
    fn xor_encryption_with_too_long_key() {
        let key: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(1501)
            .map(char::from)
            .collect();
        xor_encryption_test(format!("xor:{key}").as_str());
    }
}

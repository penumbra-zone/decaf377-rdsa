use std::convert::TryFrom;

use proptest::prelude::*;

use decaf377_rdsa::*;

proptest! {
    #[test]
    fn secretkey_serialization(
        bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let sk_result_from = SigningKey::<SpendAuth>::try_from(bytes);
        let sk_result_bincode: Result<SigningKey::<SpendAuth>, _>
            = bincode::deserialize(&bytes[..]);

        // Check 1: both decoding methods should agree
        match (sk_result_from, sk_result_bincode) {
            // Both agree on success
            (Ok(sk_from), Ok(sk_bincode)) => {
                let pk_bytes_from = VerificationKeyBytes::from(VerificationKey::from(&sk_from));
                let pk_bytes_bincode = VerificationKeyBytes::from(VerificationKey::from(&sk_bincode));
                assert_eq!(pk_bytes_from, pk_bytes_bincode);

                // Check 2: bincode encoding should match original bytes.
                let bytes_bincode = bincode::serialize(&sk_from).unwrap();
                assert_eq!(&bytes[..], &bytes_bincode[..]);

                // Check 3: From encoding should match original bytes.
                let bytes_from: [u8; 32] = sk_bincode.into();
                assert_eq!(&bytes[..], &bytes_from[..]);
            }
            // Both agree on failure
            (Err(_), Err(_)) => {},
            _ => panic!("bincode and try_from do not agree"),
        }
    }

    #[test]
    fn publickeybytes_serialization(
        bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let pk_bytes_from = VerificationKeyBytes::<SpendAuth>::from(bytes);
        let pk_bytes_bincode: VerificationKeyBytes::<SpendAuth>
            = bincode::deserialize(&bytes[..]).unwrap();

        // Check 1: both decoding methods should have the same result.
        assert_eq!(pk_bytes_from, pk_bytes_bincode);

        // Check 2: bincode encoding should match original bytes.
        let bytes_bincode = bincode::serialize(&pk_bytes_from).unwrap();
        assert_eq!(&bytes[..], &bytes_bincode[..]);

        // Check 3: From encoding should match original bytes.
        let bytes_from: [u8; 32] = pk_bytes_bincode.into();
        assert_eq!(&bytes[..], &bytes_from[..]);
    }

    #[test]
    fn publickey_serialization(
        bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let pk_result_try_from = VerificationKey::<SpendAuth>::try_from(bytes);
        let pk_result_bincode: Result<VerificationKey::<SpendAuth>, _>
            = bincode::deserialize(&bytes[..]);

        // Check 1: both decoding methods should have the same result
        match (pk_result_try_from, pk_result_bincode) {
            // Both agree on success
            (Ok(pk_try_from), Ok(pk_bincode)) => {
                // Check 2: bincode encoding should match original bytes
                let bytes_bincode = bincode::serialize(&pk_try_from).unwrap();
                assert_eq!(&bytes[..], &bytes_bincode[..]);
                // Check 3: From encoding should match original bytes
                let bytes_from: [u8; 32] = pk_bincode.into();
                assert_eq!(&bytes[..], &bytes_from[..]);
            },
            // Both agree on failure
            (Err(_), Err(_)) => {},
            _ => panic!("bincode and try_from do not agree"),
        }
    }

}

#[cfg(test)]
mod tests {
    use rustsv::wallet::derivation::*;
    use rustsv::util::Error;
    
    const SEED: &str = "697fce933855df6dc5f0490c8370157af5af4af1b5f20d5c6ec7f5c1d04b859e2389bdf68fd956fd9dede46d9aa9af114b23cec6a69c8905e84c2e6376e19eb7";
    const EXPECTED_MASTER_PRIV: &str = "xprv9s21ZrQH143K4aC15QhGLbgXYMdLskEFQ3rJ8ucq8uPE5zqoih5rSUWALU2CrgbGAQxiApmw6tE3DUgm7G2Ns2CPusPkfNKLJE7LX9TVoTs";
    // const EXPECTED_MASTER_PUB: &str = "xpub661MyMwAqRbcG1aFeagSFNez4qTtKphtoRMUwAvc2HdyJx6TD18azgdLDqNQNxxb9So1MEfG8oRn2ryuzCB4GFt87Lhh5wWy9r5g6xEVdrD";

    /// You need to know the derivation path from the master xpriv for this
    const EXPECTED_CHILD_PRIV : &str = "xprv9zPYpnKVEEdo5PJuiPNM3LjjZuJqnUd5CQ14MHr7aa26GWHDQpua1HMyJsnWg3unmmsBEQwDQPMfkDB3TtaNM6Ao4G5dGJzZzDYMWFe33LW";

    #[test]
    fn test_master_xpriv_from_seed()  -> Result<(), Error> {
        let master_keypair_1 = derive_seed_or_extended_key(SEED, "", Network::Mainnet);
        assert_eq!(
            master_keypair_1.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_2 = derive_seed_or_extended_key(SEED, "m", Network::Mainnet);
        assert_eq!(
            master_keypair_2.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_3 = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet);
        assert_eq!(
            master_keypair_3.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_4 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "", Network::Mainnet);
        assert_eq!(
            master_keypair_4.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_5 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m", Network::Mainnet);
        assert_eq!(
            master_keypair_5.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_6 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m/", Network::Mainnet);
        assert_eq!(
            master_keypair_6.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );
        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<(), Error> {
        let network = Network::Testnet;
        let keypair = derive_seed_or_extended_key(SEED, "m/", network)?;

        for (is_private, label) in [(true, ExtendedKeyType::Private), (false, ExtendedKeyType::Public)] {
            let encoded = keypair.encode(is_private);
            println!("Encoded {:?} key: {:?}", label, encoded);

            let decoded = ExtendedKeypair::decode(&encoded, network)?;
            match is_private {
                true => {
                    println!("Decoded private key: {:?}", decoded.extended_private_key);
                    assert_eq!(keypair.extended_private_key, decoded.extended_private_key);
                }
                false => {
                    println!("Decoded public key:  {:?}", decoded.extended_public_key);
                    assert_eq!(keypair.extended_public_key, decoded.extended_public_key);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_pubkey_from_xprv() -> Result<(), Error> {
        let secp = Secp256k1::new();

        let private_key_arr = ExtendedKey::get_private_key(EXPECTED_MASTER_PRIV)?;
        println!("Private key: {:?}", private_key_arr);
        let secret_key = SecretKey::from_byte_array(private_key_arr)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        println!("Public key: {}", hex::encode(public_key.serialize()));
        Ok(())
    }

    #[test]
    fn test_normal_private_derivation()  -> Result<(), Error> {
        let child = derive_seed_or_extended_key(SEED,"m/0", Network::Mainnet)?;
        assert!(
            child.extended_private_key.starts_with("xprv"),
            "Expected private key version (xprv)"
        );
        Ok(())
    }

    #[test]
    fn test_unusual_but_valid_path_writings()  -> Result<(), Error> {
        let master_keypair = derive_seed_or_extended_key(SEED, "", Network::Mainnet)?;
        let derived_keypair = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m/44/0/0/", Network::Mainnet)?;

        println!("Master  Keypair: {:?}", master_keypair);
        println!("Child   Keypair: {:?}", derived_keypair);

        assert_eq!(
            master_keypair.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Master key does not match expected value"
        );
        assert_eq!(
            derived_keypair.extended_private_key,
            EXPECTED_CHILD_PRIV,
            "Derived key does not match expected value"
        );
        assert!(
            derived_keypair.extended_private_key.starts_with("xprv"),
            "Expected private key version (xprv)"
        );

        Ok(())
    }

    #[test]
    fn test_derive_nonhardended_on_mainnet() -> Result<(), Error> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet)?;
        if master_keypair.extended_private_key != EXPECTED_MASTER_PRIV {
            println!("Master xprv dont match: {}", master_keypair.extended_private_key);
        }
        let derived_0 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/", Network::Mainnet)?;
        if derived_0.extended_private_key != EXPECTED_MASTER_PRIV {
            println!("Derived xprv dont match: {}", derived_0.extended_private_key);
        }

        let derived_1 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44", Network::Mainnet)?;
        let expected_derived_1 = "xprv9vJrExfEY674BDfrZQHQwRJjGbm6ctqVq6jZfvNw4PKTjpPSvhrATjEkxUBkD7SNYV3r9hpjXDLW5NxirMDFSRXv546brK1zpaF8kBZb9bn"; // Replace with actual derived xprv
        if derived_1.extended_private_key != expected_derived_1 {
            println!("Derived xprv dont match: {}", expected_derived_1);
        }

        let derived_3 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44/0/0", Network::Mainnet)?;
        let expected_derived_3 = "xprv9zQBrJrMTvL2moMyWteT2YcUr5cad7RUUkXtgWyMpGStCCQq1EDXDU8YmnRUrxxx59TKKx4wEuSmS1Fm7QPBHxoAM7SFRG5H1A5xTeEi4Yw"; // Replace with actual derived xprv
        if derived_3.extended_private_key != expected_derived_3 {
            println!("Derived xprv dont match: {}", derived_3.extended_private_key);
        }

        assert_eq!(
            master_keypair.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Master key does not match expected value"
        );
        assert_eq!(
            derived_0.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Derived key does not match expected value"
        );

        Ok(())
    }

    #[test]
    fn test_derivation_step_by_step_mainnet() -> Result<(), Error> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet)?;
        assert_eq!(master_keypair.extended_private_key, EXPECTED_MASTER_PRIV, "Master key mismatch");

        let m = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/", Network::Mainnet)?;
        assert_eq!(m.extended_private_key, EXPECTED_MASTER_PRIV, "Master key mismatch");

        let m_44 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44", Network::Mainnet)?;
        println!("m/44 xprv: {}", m_44.extended_private_key);
        let m_44_0 = derive_seed_or_extended_key(&m_44.extended_private_key, "m/0", Network::Mainnet)?;
        println!("m/44/0 xprv: {}", m_44_0.extended_private_key);
        let derived = derive_seed_or_extended_key(&m_44_0.extended_private_key, "m/0", Network::Mainnet)?;
        println!("m/44/0/0 xprv: {}", derived.extended_private_key);

        // let correct_expected_derived = "xprv9zPYpnKVEEdo5PJuiPNM3LjjZuJqnUd5CQ14MHr7aa26GWHDQpua1HMyJsnWg3unmmsBEQwDQPMfkDB3TtaNM6Ao4G5dGJzZzDYMWFe33LW";
        // let uncorrect_expected_derived = "xprv9zKZ4Ycu1DUYWyJqPZLh9ZYiZs3K5kpvRHXoJCUSwNFwwKVbUVH5WNUg1SJdKJxFWo9X2KGBBhJXdNecQANJAidRXrN8Mju8LzQf4KmbebU";
        assert_eq!(derived.extended_private_key, EXPECTED_CHILD_PRIV, "Derived key mismatch");
        Ok(())
    }

    #[test]
    fn test_nonhardened_derivation_on_testnet() -> Result<(), Error> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m", Network::Testnet)?;
        let derived_keypair = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44/0/0/", Network::Testnet)?;
        assert!(master_keypair.extended_private_key.starts_with("tprv"), "Expected testnet private key version (tprv)");
        assert!(derived_keypair.extended_private_key.starts_with("tprv"), "Expected testnet private key version (tprv)");
        Ok(())
    }



    // #[test]
    // fn test_hmac_manual()  -> Result<(), Error> {
    //     let private_key = [
    //         232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20, 49,
    //         56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
    //     ];
    //     let index = 0x80000000u32;
    //     let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
    //     data[0] = 0;
    //     data[1..33].copy_from_slice(&private_key[..32]);
    //     data[33..37].copy_from_slice(&index.to_be_bytes());
    //     assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

    //     // Compute input checksum
    //     let input_checksum = Sha256::digest(&data);
    //     eprintln!(
    //         "HMAC input checksum: {}",
    //         hex::encode(input_checksum.to_vec())
    //     );

    //     // Compute HMAC with ring
    //     let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, SEED.as_bytes());
    //     let result = ring_hmac::sign(&hmac_key, &data[..37]);
    //     let result_bytes = result.as_ref();
    //     eprintln!(
    //         "HMAC result: {} (len: {})",
    //         hex::encode(result_bytes),
    //         result_bytes.len()
    //     );

    //     assert_eq!(
    //         hex::encode(result_bytes),
    //         "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    //     );
    //     Ok(())
    // }

    // #[test]
    // fn test_hmac()  -> Result<(), Error> {
    //     let private_key = [
    //         232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20, 49,
    //         56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
    //     ];
    //     let index = 0x80000000u32; // Hardened index
    //     let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
    //     data[0] = 0;
    //     data[1..33].copy_from_slice(&private_key[..32]);
    //     data[33..37].copy_from_slice(&index.to_be_bytes());
    //     assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

    //     // Compute input checksum
    //     let input_checksum = Sha256::digest(&data);
    //     eprintln!(
    //         "HMAC input checksum: {}",
    //         hex::encode(input_checksum.to_vec())
    //     );

    //     // Compute HMAC with ring
    //     let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, SEED.as_bytes());
    //     let result = ring_hmac::sign(&hmac_key, &data[..37]);
    //     let result_bytes = result.as_ref();
    //     eprintln!(
    //         "HMAC result: {} (len: {})",
    //         hex::encode(result_bytes),
    //         result_bytes.len()
    //     );

    //     assert_eq!(
    //         hex::encode(result_bytes),
    //         "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    //     );
    //     Ok(())
    // }

}
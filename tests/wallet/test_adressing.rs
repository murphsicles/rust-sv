#[cfg(test)]
mod tests {
    use rustsv::wallet::adressing::*;
    use rustsv::wallet::derivation::Network;
    use rustsv::util::Error;
    use base58::FromBase58; // Added missing import

    const EXTENDED_DERIVATIONPATH : &str = "m/44/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;4':35;5H:55;6h:66]";

    #[test]
    fn test_extract_brackets(){
        match extract_brackets(EXTENDED_DERIVATIONPATH) {
            Some(bracket_content) => println!("test_extract_brackets - Bracket Content: [{}]", bracket_content),
            None => println!("No brackets found"),
        }
    }

    #[test]
    fn test_exclude_brackets(){
        let derivationpath = exclude_brackets(EXTENDED_DERIVATIONPATH);
        println!("Derivation Path (normalized): {}", derivationpath);
        assert_eq!(derivationpath, "m/44/0/0", "Derivation path does not match expected value");
    }
  
    #[test]
    fn test_extract_typeindex() {
        let bracket_content = "0:70-105;1H:0,1,2,3,4,5,6,7;2:200-300;2h:400-500;3':600-700";

        let result1 = extract_typeindex(bracket_content, "0");
        println!("{:?}", result1); // Outputs: Some("70-105")

        // Hardened index
        let result2 = extract_typeindex(bracket_content, "1H");
        println!("{:?}", result2); // Outputs: Some("0,1,2,3,4,5,6,7")

        // Hardened index
        let result3 = extract_typeindex(bracket_content, "2h");
        println!("{:?}", result3); // Outputs: Some("400-500")

        // Hardened index
        let result4 = extract_typeindex(bracket_content, "3'");
        println!("{:?}", result4); // Outputs: Some("600-700")

        // Non-hardened index
        let result5 = extract_typeindex(bracket_content, "2");
        println!("{:?}", result5); // Outputs: Some("200-300")

        // Non-existent index
        let result6 = extract_typeindex(bracket_content, "4");
        println!("{:?}", result6); // Outputs: None
    }

    #[test]
    fn test_extract_with_nonhardended_typeindex() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH);
        match bracket_content {
            Some(content) => {
                let typeindex = "2";
                let result = extract_typeindex(&content, typeindex);
                println!("Get Values of TypeIndex {:?} : {:?}", typeindex, result);
                assert_eq!(
                    result,
                    Some("0,1,2,3,4,5,6,7".to_string()),
                    "Expected value for typeindex {} does not match",
                    typeindex
                );

                // Test for non-existent typeindex
                let typeindex = "15";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, None, "Expected None for non-existent typeindex");
            }
            None => panic!("Expected bracket content but found None"),
        }
    }

    #[test]
    fn test_extract_with_hardended_typeindex() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH);
        match bracket_content {
            Some(content) => {
                let typeindex = "0";
                let result = extract_typeindex(&content, typeindex);
                println!("Get Values of TypeIndex {:?} : {:?}", typeindex, result);
                assert_eq!(
                    result,
                    Some("70-105".to_string()),
                    "Expected value for typeindex {} does not match",
                    typeindex
                );

                let typeindex = "4'";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("35".to_string()), "Expected None for non-existent typeindex");

                let typeindex = "5H";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("55".to_string()), "Expected None for non-existent typeindex");

                let typeindex = "6h";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("66".to_string()), "Expected None for non-existent typeindex");

                // Test for non-existent typeindex
                let typeindex = "15";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, None, "Expected None for non-existent typeindex");
            }
            None => panic!("Expected bracket content but found None"),
        }
    }

    #[test]
    fn test_get_indexes_in_array() {
        // Test range format
        let result = get_indexes_in_array("8-11").unwrap();
        assert_eq!(result, vec![8, 9, 10, 11], "Range 8-11 failed");

        // Test comma-separated list
        let result = get_indexes_in_array("0,1,2,3,4,5,6,7").unwrap();
        assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7], "Comma-separated list failed");

        // Test single number
        let result = get_indexes_in_array("30").unwrap();
        assert_eq!(result, vec![30], "Single number failed");

        // Test invalid range
        assert!(get_indexes_in_array("11-8").is_err(), "Invalid range should fail");

        // Test invalid number
        assert!(get_indexes_in_array("a-11").is_err(), "Invalid number in range should fail");

        // Test invalid list
        assert!(get_indexes_in_array("0,1,a,3").is_err(), "Invalid number in list should fail");

        // TEST MOAR ADVANCED STUFF
    }

    #[test]
    fn test_extended_derivationpath_to_index_array() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH).expect("Failed to extract brackets");
        let typeindex = "0";
        let typeindex_content = extract_typeindex(&bracket_content, typeindex).expect("Failed to extract typeindex 0");
        println!("test_extended_derivationpath_to_index_array - Bracket Content: {}", typeindex_content);
        let result = get_indexes_in_array(&typeindex_content).unwrap();
        println!("Result for Array: {:?}", result);
        assert_eq!(
            result,
            vec![70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105],
            "Parsing typeindex {} failed",
            typeindex
        );
    }

    #[test]
    fn test_more_advanced_combinations() {
        let advanced_extended_derivatonpath = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
        let bracket_content = extract_brackets(advanced_extended_derivatonpath).expect("Failed to extract brackets");
        let typeindex = "0";
        let typeindex_content = extract_typeindex(&bracket_content, typeindex).expect("Failed to extract typeindex 0");
        println!("test_more_advanced_combinations - Bracket Content: {}", typeindex_content);
        let result = get_indexes_in_array(&typeindex_content).unwrap();
        println!("test_more_advanced_combinations - Result for Array: {:?}", result);
        assert_eq!(
                result,
                (69..=120).collect::<Vec<usize>>(),
                "Parsing typeindex {} failed",
                typeindex
            );
    }

    #[test]
    fn test_get_typeindex_indices() {
        let advanced_extended_derivatonpath = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
        let typeindex = "0";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<usize>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }

        let advanced_extended_derivatonpath = "m/69'/0'/0'/[1H:70-105,90-120,88,69,70-75;]";
        let typeindex = "1H";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<usize>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }

        let advanced_extended_derivatonpath = "m/69'/0'/0'/[2':70-105,90-120,88,69,70-75;]";
        let typeindex = "2'";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<usize>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }


        let advanced_extended_derivatonpath = "m/69'/0'/0'/[3h:70-105,90-120,88,69,70-75;]";
        let typeindex = "3h";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<usize>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }


    }

    ///  
    const EXTENDED_KEY : &str = "xprv9s21ZrQH143K3XVnYZ9RtEiFWodPvMz3SCRt8nWzTx6zS9mJfTpLStJrNa2Bd9v8kwFdDJkWizK62FBmRGDW8MEZciMBzw3zMwZcXophEF6";
    const ADVANCED_EXTENDED_DERIVATIONPATH : &str = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
    const TYPEINDEX : &str = "0";
    const NETWORK : Network = Network::Mainnet;

    #[test]
    fn test_get_adresse_array_from_extended_derivationpath() {

        // Get the result from the function being tested
        let result = get_adresse_array_from_extended_derivationpath(
            EXTENDED_KEY,
            ADVANCED_EXTENDED_DERIVATIONPATH,
            TYPEINDEX,
            NETWORK,
        );

        // Get public keys for comparison
        let compare_pk = get_publickey_array_from_extended_derivationpath(
            EXTENDED_KEY,
            ADVANCED_EXTENDED_DERIVATIONPATH,
            TYPEINDEX,
            NETWORK,
        );

        // Convert public keys to P2PKH addresses
        let compare_adresse = match compare_pk {
            Ok(pubkeys) => pubkeys
                .into_iter()
                .map(|pubkey_hex| {
                    // Decode hex-encoded public key
                    let pubkey_bytes = hex::decode(pubkey_hex)?;
                    // Generate P2PKH address
                    public_key_to_p2pkh_address(&pubkey_bytes, NETWORK)
                })
                .collect::<Result<Vec<String>, _>>(),
            Err(e) => Err(e),
        };

        println!(
            "test_get_address_array_from_extended_derivationpath - Result: {:?}",
            result
        );

        match (result, compare_adresse) {
            (Ok(value), Ok(compare)) => assert_eq!(
                value,
                compare,
                "Parsing typeindex {} failed",
                TYPEINDEX
            ),
            (Err(e), _) => panic!("Parsing typeindex {} failed: {:?}", TYPEINDEX, e),
            (_, Err(e)) => panic!("Comparison address derivation failed: {:?}", e),
        }
    }

    //////
    #[test]
    fn test_encode_decode_p2pkh() -> Result<(), Error> {
        let pubkey_hash: [u8; 20] = hex::decode("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")?
            .try_into()
            .unwrap();
        let address = encode_p2pkh_address(Network::Mainnet, &pubkey_hash)?;
        assert_eq!(address, "13PNN3hx4wxHBLFwLNNwmKxD6V5jFZQo6s");
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, constants::MAINNET_P2PKH_VERSION);
        assert_eq!(decoded, pubkey_hash.to_vec());
        Ok(())
    }

    #[test]
    fn test_encode_decode_p2sh() -> Result<(), Error> {
        let script_hash: [u8; 20] = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")?
            .try_into()
            .unwrap();
        let address = encode_p2sh_address(Network::Testnet, &script_hash)?;
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, constants::TESTNET_P2SH_VERSION);
        assert_eq!(decoded, script_hash.to_vec());
        Ok(())
    }

    #[test]
    fn test_validate_address() -> Result<(), Error> {
        let valid_mainnet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let valid_testnet = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        validate_address(Network::Mainnet, valid_mainnet)?;
        validate_address(Network::Testnet, valid_testnet)?;
        assert!(validate_address(Network::Mainnet, valid_testnet).is_err());
        Ok(())
    }

    ////
    #[test]
    fn test_get_unused_address() -> Result<(), Error> {
        // Mock inputs
        let extended_key = "xprv9s21ZrQH143K3XVnYZ9RtEiFWodPvMz3SCRt8nWzTx6zS9mJfTpLStJrNa2Bd9v8kwFdDJkWizK62FBmRGDW8MEZciMBzw3zMwZcXophEF6"; // xpriv, no xpub
        let extended_derivation_path = "m/44'/0'/0'/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]";
        let shorted_derivation_path = "path/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]";
        let type_index = "0";
        let gap_limit = 20;

        // Test case 1: pk_or_bitcoin_address = true (returns hex-encoded public key)
        {
            let result = get_unused_address(
                extended_key,
                extended_derivation_path,
                type_index,
                Network::Mainnet,
                gap_limit,
                true, // Return hex-encoded public key
            )?;
            // Verify the result is a valid hex string
            assert!(
                hex::decode(&result).is_ok(),
                "Public key should be a valid hex string"
            );
            // Compressed public key should be 66 characters (33 bytes * 2 for hex)
            assert_eq!(
                result.len(),
                66,
                "Public key should be 66 characters (compressed key)"
            );
            // Check if it starts with "02" or "03" (compressed public key prefix)
            assert!(
                result.starts_with("02") || result.starts_with("03"),
                "Public key should start with '02' or '03' for compressed key"
            );

            println!("Mainnet Compressed Public Key {}", result);
        }

        // Test case 2: pk_or_bitcoin_address = false (returns Mainnet P2PKH address)
        {
            let result = get_unused_address(
                extended_key,
                extended_derivation_path,
                type_index,
                Network::Mainnet,
                gap_limit,
                false, // Return P2PKH address
            )?;
            // Verify the address is valid Base58Check
            let decoded = result
                .from_base58()
                .map_err(|e| Error::FromBase58Error(e))?;
            assert_eq!(
                decoded.len(),
                25,
                "P2PKH address should decode to 25 bytes"
            );
            // Use decode_address to validate checksum and version
            let (version, _) = decode_address(&result)?;
            // Check version byte matches Mainnet P2PKH
            assert_eq!(
                version,
                constants::MAINNET_P2PKH_VERSION,
                "Address version should match Mainnet P2PKH"
            );
            // Check address starts with '1' for Mainnet P2PKH
            assert!(
                result.starts_with("1"),
                "Mainnet P2PKH address should start with '1'"
            );

            println!("Mainnet P2PKH address {}", result);
        }

        // Test case 3: Testnet address (pk_or_bitcoin_address = false)
        // {
        //     let result = get_unused_address(
        //         extended_key,
        //         extended_derivation_path,
        //         type_index,
        //         Network::Testnet,
        //         gap_limit,
        //         false, // Return P2PKH address
        //     )?;
        //     // Verify the address is valid Base58Check
        //     let decoded = result
        //         .from_base58()
        //         .map_err(|e| Error::FromBase58Error(e))?;
        //     assert_eq!(
        //         decoded.len(),
        //         25,
        //         "P2PKH address should decode to 25 bytes"
        //     );
        //     // Use decode_address to validate checksum and version
        //     let (version, _) = decode_address(&result)?;
        //     // Check version byte matches Testnet P2PKH
        //     assert_eq!(
        //         version,
        //         constants::TESTNET_P2PKH_VERSION,
        //         "Address version should match Testnet P2PKH"
        //     );
        //     // Check address starts with 'm' or 'n' for Testnet P2PKH
        //     assert!(
        //         result.starts_with("m") || result.starts_with("n"),
        //         "Testnet P2PKH address should start with 'm' or 'n'"
        //     );
        // }

        // Test case 1.path: pk_or_bitcoin_address = true (returns hex-encoded public key)
        {
            let result = get_unused_address(
                extended_key,
                shorted_derivation_path,
                type_index,
                Network::Mainnet,
                gap_limit,
                true, // Return hex-encoded public key
            )?;
            // Verify the result is a valid hex string
            assert!(
                hex::decode(&result).is_ok(),
                "Public key should be a valid hex string"
            );
            // Compressed public key should be 66 characters (33 bytes * 2 for hex)
            assert_eq!(
                result.len(),
                66,
                "Public key should be 66 characters (compressed key)"
            );
            // Check if it starts with "02" or "03" (compressed public key prefix)
            assert!(
                result.starts_with("02") || result.starts_with("03"),
                "Public key should start with '02' or '03' for compressed key"
            );

            println!("Mainnet Compressed Public Key {}", result);
        }

        // Test case 2.path: pk_or_bitcoin_address = false (returns Mainnet P2PKH address)
        {
            let result = get_unused_address(
                extended_key,
                shorted_derivation_path,
                type_index,
                Network::Mainnet,
                gap_limit,
                false, // Return P2PKH address
            )?;
            // Verify the address is valid Base58Check
            let decoded = result
                .from_base58()
                .map_err(|e| Error::FromBase58Error(e))?;
            assert_eq!(
                decoded.len(),
                25,
                "P2PKH address should decode to 25 bytes"
            );
            // Use decode_address to validate checksum and version
            let (version, _) = decode_address(&result)?;
            // Check version byte matches Mainnet P2PKH
            assert_eq!(
                version,
                constants::MAINNET_P2PKH_VERSION,
                "Address version should match Mainnet P2PKH"
            );
            // Check address starts with '1' for Mainnet P2PKH
            assert!(
                result.starts_with("1"),
                "Mainnet P2PKH address should start with '1'"
            );

            println!("Mainnet P2PKH address {}", result);
        }

        Ok(())
    }
}
// Step 0: From Entropy to Mnemonic
// Step 1: From Mnemonic to Seed
pub mod test_mnemonic;

// Step 2: From Seed to Master Extended Keypair
// Step 3: From Master Extended Keypair to Child Extended Keypair
pub mod test_derivation;

// Step 4:From Child Extended Keypair to Adresse Parameter
pub mod test_adressing;

// Step 5: Get Balance
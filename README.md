# NethreumExamples
A list of Nethereum Scripts for creating Web3 Games in .Net

Main Class
The Wallets class contains the main logic for generating and managing Ethereum wallets. Here's an overview of the key methods:

GeneratePrivateKey(): Generates a new Ethereum private key.
GenerateMnemonic(EthECKey ecKey): Generates a mnemonic from the given private key.
GenerateRandomMessage(string[] wordList): Generates a random message using the given word list.
SignMessage(EthECKey ecKey, string message): Signs the given message using the provided private key.
EncryptPrivateKeyWithSalt(byte[] privateKeyBytes, byte[] password, out byte[] salt): Encrypts the private key using AES encryption with a derived key from the password and salt.
DecryptPrivateKeyWithSalt(string encryptedPrivateKey, byte[] password, byte[] salt): Decrypts the private key using AES decryption with a derived key from the password and salt.
EncryptStringWithSalt(string plainText, byte[] password, out byte[] salt): Encrypts a string using AES encryption with a derived key from the password and salt.
DecryptStringWithSalt(string encryptedText, byte[] password, byte[] salt): Decrypts a string using AES decryption with a derived key from the password and salt.
HandleUserInput(string[] words, EthECKey ecKey, string message, string signature, string encryptedPrivateKey, string encryptedMnemonic, byte[] hashedSignature, byte[] privateKeySalt, byte[] mnemonicSalt): Handles user input to verify the mnemonic and decrypt the private key.
ValidateUserInput(string[] userInputs, List<dynamic> selectedWords): Validates the user input against the selected mnemonic words.
VerifyAndDecryptPrivateKey(EthECKey ecKey, string message, string encryptedPrivateKey, string encryptedMnemonic, string signature, byte[] privateKeySalt, byte[] mnemonicSalt): Verifies the message signature and decrypts the private key and mnemonic.
ComputeSha256Hash(string rawData): Computes the SHA256 hash of the given string.
RetrieveAccount(string mnemonic, byte[] password, int index): Retrieves an Ethereum account using the mnemonic and password.


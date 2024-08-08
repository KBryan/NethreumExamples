using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Nethereum.HdWallet;
using NBitcoin;
using System.Collections.Generic;
using Nethereum.Web3.Accounts;

namespace WalletGenerator
{
    /// <summary>
    /// This class contains methods to generate and manage Ethereum wallets, including private key encryption and decryption.
    /// </summary>
    class Wallets
    {
        /// <summary>
        /// Main entry point of the Wallets class.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        static void Main(string[] args)
        {
            try
            {
                var ecKey = GeneratePrivateKey();
                var mnemonic = GenerateMnemonic(ecKey);
                var message = GenerateRandomMessage(mnemonic.Words);
                var signature = SignMessage(ecKey, message);
                var hashedSignature = ComputeSha256Hash(signature);

                var encryptedPrivateKey = EncryptPrivateKeyWithSalt(ecKey.GetPrivateKeyAsBytes(), hashedSignature, out var privateKeySalt);
                var encryptedMnemonic = EncryptStringWithSalt(mnemonic.ToString(), hashedSignature, out var mnemonicSalt);

                DisplaySplitPrivateKey(ecKey.GetPrivateKeyAsBytes());
                HandleUserInput(mnemonic.Words, ecKey, message, signature, encryptedPrivateKey, encryptedMnemonic, hashedSignature, privateKeySalt, mnemonicSalt);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occurred: {e.Message}");
            }
        }

        /// <summary>
        /// Generates a new Ethereum private key.
        /// </summary>
        /// <returns>Returns an instance of EthECKey containing the generated private key.</returns>
        static EthECKey GeneratePrivateKey()
        {
            var ecKey = EthECKey.GenerateKey();
            var privateKeyHex = ecKey.GetPrivateKeyAsBytes().ToHex();
            Console.WriteLine($"Private Key: {privateKeyHex}");
            return ecKey;
        }

        /// <summary>
        /// Generates a mnemonic from the given Ethereum private key.
        /// </summary>
        /// <param name="ecKey">The Ethereum private key.</param>
        /// <returns>Returns a mnemonic instance.</returns>
        static Mnemonic GenerateMnemonic(EthECKey ecKey)
        {
            var entropy = ecKey.GetPrivateKeyAsBytes();
            var mnemonic = new Mnemonic(Wordlist.English, entropy);
            Console.WriteLine($"Mnemonic: {mnemonic}");
            return mnemonic;
        }

        /// <summary>
        /// Generates a random message using the given word list.
        /// </summary>
        /// <param name="wordList">The list of words to use for generating the message.</param>
        /// <returns>Returns the generated random message.</returns>
        static string GenerateRandomMessage(string[] wordList)
        {
            var random = new Random();
            int wordCount = random.Next(5, 15); // Randomly choose between 5 and 15 words
            var selectedWords = new List<string>();

            for (int i = 0; i < wordCount; i++)
            {
                var randomWord = wordList[random.Next(wordList.Length)];
                selectedWords.Add(randomWord);
            }

            var message = string.Join(" ", selectedWords);
            Console.WriteLine($"Random Message: {message}");
            return message;
        }

        /// <summary>
        /// Signs the given message using the provided Ethereum private key.
        /// </summary>
        /// <param name="ecKey">The Ethereum private key.</param>
        /// <param name="message">The message to sign.</param>
        /// <returns>Returns the signed message.</returns>
        static string SignMessage(EthECKey ecKey, string message)
        {
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(message, ecKey);
            Console.WriteLine($"Signed Message: {signature}");
            return signature;
        }

        /// <summary>
        /// Displays the private key in three parts for security.
        /// </summary>
        /// <param name="privateKeyBytes">The private key in byte array format.</param>
        static void DisplaySplitPrivateKey(byte[] privateKeyBytes)
        {
            int partLength = privateKeyBytes.Length / 3;
            var part1 = privateKeyBytes.Take(partLength).ToArray();
            var part2 = privateKeyBytes.Skip(partLength).Take(partLength).ToArray();
            var part3 = privateKeyBytes.Skip(2 * partLength).ToArray();

            Console.WriteLine($"Private Key Part 1: {part1.ToHex()}");
            Console.WriteLine($"Private Key Part 2: {part2.ToHex()}");
            Console.WriteLine($"Private Key Part 3: {part3.ToHex()}");

            var combinedPrivateKeyBytes = part1.Concat(part2).Concat(part3).ToArray();
            var combinedPrivateKeyHex = combinedPrivateKeyBytes.ToHex();

            if (combinedPrivateKeyHex == privateKeyBytes.ToHex())
            {
                Console.WriteLine("Private key successfully split and recombined.");
            }
            else
            {
                Console.WriteLine("Error in recombining the private key.");
            }
        }

        /// <summary>
        /// Handles user input to verify the mnemonic and decrypt the private key.
        /// </summary>
        /// <param name="words">The mnemonic words.</param>
        /// <param name="ecKey">The Ethereum private key.</param>
        /// <param name="message">The signed message.</param>
        /// <param name="signature">The message signature.</param>
        /// <param name="encryptedPrivateKey">The encrypted private key.</param>
        /// <param name="encryptedMnemonic">The encrypted mnemonic.</param>
        /// <param name="hashedSignature">The hashed signature used as a password.</param>
        /// <param name="privateKeySalt">The salt used for encrypting the private key.</param>
        /// <param name="mnemonicSalt">The salt used for encrypting the mnemonic.</param>
        static void HandleUserInput(string[] words, EthECKey ecKey, string message, string signature, string encryptedPrivateKey, string encryptedMnemonic, byte[] hashedSignature, byte[] privateKeySalt, byte[] mnemonicSalt)
        {
            var random = new Random();
            var positions = Enumerable.Range(0, words.Length).OrderBy(x => random.Next()).Take(6).ToList();
            var selectedWords = positions.Select(pos => new { Word = words[pos], Position = pos + 1 }).Cast<dynamic>().ToList();
            Console.WriteLine("Selected words and positions (for debugging): " + string.Join(", ", selectedWords.Select(sw => $"{sw.Word} at position {sw.Position}")));

            var userInputs = new List<string>();
            foreach (var sw in selectedWords)
            {
                string? userInput = null;
                while (string.IsNullOrEmpty(userInput))
                {
                    Console.Write($"Enter the word at position {sw.Position}: ");
                    userInput = Console.ReadLine();
                    if (!string.IsNullOrEmpty(userInput))
                    {
                        userInputs.Add(userInput);
                    }
                    else
                    {
                        Console.WriteLine("Input cannot be empty. Please enter a valid word.");
                    }
                }
            }

            bool isValid = ValidateUserInput(userInputs.ToArray(), selectedWords);
            if (isValid)
            {
                Console.WriteLine($"Congratulations! You entered the correct words.\nThe account {ecKey.GetPublicAddress()} has been funded with 10 Coins");
            }
            else
            {
                Console.WriteLine("Sorry, the words you entered are incorrect.");
            }

            VerifyAndDecryptPrivateKey(ecKey, message, encryptedPrivateKey, encryptedMnemonic, signature, privateKeySalt, mnemonicSalt);
        }

        /// <summary>
        /// Verifies the message signature and decrypts the private key and mnemonic.
        /// </summary>
        /// <param name="ecKey">The Ethereum private key.</param>
        /// <param name="message">The signed message.</param>
        /// <param name="encryptedPrivateKey">The encrypted private key.</param>
        /// <param name="encryptedMnemonic">The encrypted mnemonic.</param>
        /// <param name="signature">The message signature.</param>
        /// <param name="privateKeySalt">The salt used for encrypting the private key.</param>
        /// <param name="mnemonicSalt">The salt used for encrypting the mnemonic.</param>
        static void VerifyAndDecryptPrivateKey(EthECKey ecKey, string message, string encryptedPrivateKey, string encryptedMnemonic, string signature, byte[] privateKeySalt, byte[] mnemonicSalt)
        {
            Console.Write("Enter the signed message: ");
            string? userProvidedSignature = Console.ReadLine();
            if (string.IsNullOrEmpty(userProvidedSignature))
            {
                Console.WriteLine("Invalid signature input.");
                return;
            }

            var signer = new EthereumMessageSigner();
            var recoveredAddress = signer.EncodeUTF8AndEcRecover(message, userProvidedSignature);
            if (recoveredAddress == ecKey.GetPublicAddress())
            {
                Console.WriteLine("Message signature verified.");

                var userHashedSignature = ComputeSha256Hash(userProvidedSignature);
                var decryptedPrivateKeyBytes = DecryptPrivateKeyWithSalt(encryptedPrivateKey, userHashedSignature, privateKeySalt);
                var decryptedPrivateKeyHex = decryptedPrivateKeyBytes.ToHex();
                Console.WriteLine($"Decrypted Private Key: {decryptedPrivateKeyHex}");

                if (decryptedPrivateKeyHex == ecKey.GetPrivateKeyAsBytes().ToHex())
                {
                    Console.WriteLine("Private key successfully decrypted and matches the original.");

                    var decryptedMnemonic = DecryptStringWithSalt(encryptedMnemonic, userHashedSignature, mnemonicSalt);
                    var retrievedAccount = RetrieveAccount(decryptedMnemonic, userHashedSignature, 0);
                    Console.WriteLine($"Retrieved Account Address: {retrievedAccount.Address}");
                    Console.WriteLine($"Retrieved Account Private Key: {retrievedAccount.PrivateKey}");
                }
                else
                {
                    Console.WriteLine("Decrypted private key does not match the original.");
                }
            }
            else
            {
                Console.WriteLine("Failed to verify the message signature.");
            }
        }

        /// <summary>
        /// Computes the SHA256 hash of the given string.
        /// </summary>
        /// <param name="rawData">The input string to hash.</param>
        /// <returns>Returns the computed SHA256 hash as a byte array.</returns>
        static byte[] ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            }
        }

        /// <summary>
        /// Encrypts the private key using AES encryption with a derived key from the password and salt.
        /// </summary>
        /// <param name="privateKeyBytes">The private key to encrypt as a byte array.</param>
        /// <param name="password">The password used for encryption.</param>
        /// <param name="salt">The salt used for encryption, output parameter.</param>
        /// <returns>Returns the encrypted private key as a Base64 string.</returns>
        static string EncryptPrivateKeyWithSalt(byte[] privateKeyBytes, byte[] password, out byte[] salt)
        {
            using (Aes aes = Aes.Create())
            {
                salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
                aes.Key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32); // Derive key using salt
                aes.GenerateIV();
                byte[] iv = aes.IV;
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(salt, 0, salt.Length); // Write salt to the output stream
                        ms.Write(iv, 0, iv.Length); // Write IV to the output stream
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(privateKeyBytes, 0, privateKeyBytes.Length);
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the private key using AES decryption with a derived key from the password and salt.
        /// </summary>
        /// <param name="encryptedPrivateKey">The encrypted private key as a Base64 string.</param>
        /// <param name="password">The password used for decryption.</param>
        /// <param name="salt">The salt used for decryption.</param>
        /// <returns>Returns the decrypted private key as a byte array.</returns>
        static byte[] DecryptPrivateKeyWithSalt(string encryptedPrivateKey, byte[] password, byte[] salt)
        {
            byte[] fullCipher = Convert.FromBase64String(encryptedPrivateKey);
            using (Aes aes = Aes.Create())
            {
                byte[] iv = new byte[aes.BlockSize / 8];
                byte[] cipherText = new byte[fullCipher.Length - salt.Length - iv.Length];

                Buffer.BlockCopy(fullCipher, 0, salt, 0, salt.Length); // Read salt
                Buffer.BlockCopy(fullCipher, salt.Length, iv, 0, iv.Length); // Read IV
                Buffer.BlockCopy(fullCipher, salt.Length + iv.Length, cipherText, 0, cipherText.Length); // Read ciphertext

                aes.Key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32); // Derive key using salt
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream(cipherText))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var br = new BinaryReader(cs))
                            {
                                return br.ReadBytes(cipherText.Length);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts a string using AES encryption with a derived key from the password and salt.
        /// </summary>
        /// <param name="plainText">The plaintext string to encrypt.</param>
        /// <param name="password">The password used for encryption.</param>
        /// <param name="salt">The salt used for encryption, output parameter.</param>
        /// <returns>Returns the encrypted string as a Base64 string.</returns>
        static string EncryptStringWithSalt(string plainText, byte[] password, out byte[] salt)
        {
            using (Aes aes = Aes.Create())
            {
                salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
                aes.Key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32); // Derive key using salt
                aes.GenerateIV();
                byte[] iv = aes.IV;
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(salt, 0, salt.Length); // Write salt to the output stream
                        ms.Write(iv, 0, iv.Length); // Write IV to the output stream
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (var sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a string using AES decryption with a derived key from the password and salt.
        /// </summary>
        /// <param name="encryptedText">The encrypted string as a Base64 string.</param>
        /// <param name="password">The password used for decryption.</param>
        /// <param name="salt">The salt used for decryption.</param>
        /// <returns>Returns the decrypted plaintext string.</returns>
        static string DecryptStringWithSalt(string encryptedText, byte[] password, byte[] salt)
        {
            byte[] fullCipher = Convert.FromBase64String(encryptedText);
            using (Aes aes = Aes.Create())
            {
                byte[] iv = new byte[aes.BlockSize / 8];
                byte[] cipherText = new byte[fullCipher.Length - salt.Length - iv.Length];

                Buffer.BlockCopy(fullCipher, 0, salt, 0, salt.Length); // Read salt
                Buffer.BlockCopy(fullCipher, salt.Length, iv, 0, iv.Length); // Read IV
                Buffer.BlockCopy(fullCipher, salt.Length + iv.Length, cipherText, 0, cipherText.Length); // Read ciphertext

                aes.Key = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32); // Derive key using salt
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream(cipherText))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var sr = new StreamReader(cs))
                            {
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Validates the user input against the selected mnemonic words.
        /// </summary>
        /// <param name="userInputs">The user input words.</param>
        /// <param name="selectedWords">The selected mnemonic words with their positions.</param>
        /// <returns>Returns true if the user inputs match the selected words; otherwise, false.</returns>
        static bool ValidateUserInput(string[] userInputs, List<dynamic> selectedWords)
        {
            if (userInputs == null || selectedWords == null || userInputs.Length != selectedWords.Count)
            {
                return false;
            }

            for (int i = 0; i < userInputs.Length; i++)
            {
                if (userInputs[i] != selectedWords[i].Word)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Retrieves an Ethereum account using the mnemonic and password.
        /// </summary>
        /// <param name="mnemonic">The mnemonic.</param>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="index">The account index.</param>
        /// <returns>Returns the Ethereum account.</returns>
        static Account RetrieveAccount(string mnemonic, byte[] password, int index)
        {
            var wallet = new Wallet(mnemonic, Encoding.UTF8.GetString(password));
            return wallet.GetAccount(index);
        }
    }
}

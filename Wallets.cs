using System;
using System.Linq;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Nethereum.HdWallet;
using NBitcoin;
using System.Collections.Generic;
using Nethereum.Web3.Accounts;

namespace WalletGenerator
{
    class Wallets
    {
        static void Main(string[] args)
        {
            try
            {
                // Generate a random private key
                var ecKey = EthECKey.GenerateKey();
                var privateKey = ecKey.GetPrivateKeyAsBytes().ToHex();
                Console.WriteLine($"Private Key: {privateKey}");

                // Generate mnemonic from entropy
                var entropy = ecKey.GetPrivateKeyAsBytes();
                var mnemonic = new Mnemonic(Wordlist.English, entropy);
                Console.WriteLine($"Mnemonic: {mnemonic}");

                // Password for the wallet
                string password = "password123"; // For demonstration purposes, use a secure method to handle passwords.

                // Derive private key from mnemonic with password
                var wallet = new Wallet(mnemonic.ToString(), password);
                var account = wallet.GetAccount(0);
                var derivedPrivateKey = account.PrivateKey;
                Console.WriteLine($"Derived Private Key: {derivedPrivateKey}");

                // Generate the Ethereum Address
                var address = ecKey.GetPublicAddress();
                Console.WriteLine($"Ethereum Address: {account.Address}");

                // Select 6 random words and their positions from the mnemonic
                var words = mnemonic.Words;
                var random = new Random();
                var positions = Enumerable.Range(0, words.Length).OrderBy(x => random.Next()).Take(6).ToList();
                var selectedWords = positions.Select(pos => new { Word = words[pos], Position = pos + 1 }).ToList();

                // Print selected words and positions for reference (this would not be shown to the user in a real game)
                Console.WriteLine("Selected words and positions (for debugging): " + string.Join(", ", selectedWords.Select(sw => $"{sw.Word} at position {sw.Position}")));

                // Prompt user to input the words at specific positions
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

                // Validate user input
                bool isValid = true;
                for (int i = 0; i < 6; i++)
                {
                    if (userInputs[i] != selectedWords[i].Word)
                    {
                        isValid = false;
                        break;
                    }
                }

                if (isValid)
                {
                    Console.WriteLine("Congratulations! You entered the correct words.");
                }
                else
                {
                    Console.WriteLine("Sorry, the words you entered are incorrect.");
                }

                // Retrieve account using mnemonic and password
                var retrievedAccount = RetrieveAccount(mnemonic.ToString(), password, 0);
                Console.WriteLine($"Retrieved Account Address: {retrievedAccount.Address}");
                Console.WriteLine($"Retrieved Account Private Key: {retrievedAccount.PrivateKey}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Wallets.Main: e={e}");
            }
        }

        static Account RetrieveAccount(string mnemonic, string password, int index)
        {
            var wallet = new Wallet(mnemonic, password);
            return wallet.GetAccount(index);
        }
    }
}

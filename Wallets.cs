using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Nethereum.HdWallet;
using NBitcoin;

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

                // Derive private key from mnemonic
                var wallet = new Wallet(mnemonic.ToString(), null);
                var account = wallet.GetAccount(0);
                var derivedPrivateKey = account.PrivateKey;
                Console.WriteLine($"Derived Private Key: {derivedPrivateKey}");

                // Generate the Ethereum Address
                var address = ecKey.GetPublicAddress();
                Console.WriteLine($"Ethereum Address: {address}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Wallets.Main: e={e}");
            }
        }
    }
}

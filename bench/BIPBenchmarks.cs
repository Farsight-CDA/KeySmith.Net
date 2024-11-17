using BenchmarkDotNet.Attributes;
using Keysmith.Net.BIP;
using Nethereum.HdWallet;
using Nethereum.Web3.Accounts;

namespace Keysmith.Net.Bench;
[MemoryDiagnoser]
[ShortRunJob]
public class BIPBenchmarks
{
    private readonly string _mnemonic;
    private readonly byte[] _seed;

    public BIPBenchmarks()
    {
        _mnemonic = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";
        _seed = BIP39.MnemonicToSeed(_mnemonic);
    }

    [Benchmark]
    public (byte[], byte[]) Keysmith_BIP32_DerivePath_Ethereum()
        => BIP32.DerivePath(
            BIP32Curves.Secp256k1,
            _seed,
            "m/44'/60'/0'/0/0"
        );

    [Benchmark]
    public byte[] Keysmith_BIP39_MnemonicToSeed()
        => BIP39.MnemonicToSeed(_mnemonic);
}

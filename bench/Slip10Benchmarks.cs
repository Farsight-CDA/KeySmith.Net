using BenchmarkDotNet.Attributes;
using Keysmith.Net.BIP;
using Keysmith.Net.EC;
using Keysmith.Net.ED;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Bench;
[MemoryDiagnoser]
[ShortRunJob]
public class Slip10Benchmarks
{
    private readonly byte[] _keyBuffer = new byte[32];
    private readonly byte[] _chainCodeBuffer = new byte[32];

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_Slip10_Secp256k1_Ethereum_512B()
        => Slip10.DerivePath(
            Secp256k1.Instance,
            TestData.Seed_512B,
            "m/44'/60'/0'/0/0"
        );

    [Benchmark]
    public bool Keysmith_Span_Slip10_Secp256k1_Ethereum_512B()
    {
        Span<uint> path = stackalloc uint[5];
        BIP44.Ethereum(path);
        return Slip10.TryDerivePath(
            Secp256k1.Instance,
            TestData.Seed_512B,
            _keyBuffer,
            _chainCodeBuffer,
            path
        );
    }

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_Slip10_ED25519_Solana_512B()
        => Slip10.DerivePath(
            ED25519.Instance,
            TestData.Seed_512B,
            "m/44'/501'/0'/0'"
        );

    [Benchmark]
    public bool Keysmith_Span_Slip10_ED25519_Solana_512B()
    {
        Span<uint> path = stackalloc uint[4];
        BIP44.Solana(path);
        return Slip10.TryDerivePath(
            ED25519.Instance,
            TestData.Seed_512B,
            _keyBuffer,
            _chainCodeBuffer,
            path
        );
    }
}

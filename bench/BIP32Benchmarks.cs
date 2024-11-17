using BenchmarkDotNet.Attributes;
using Keysmith.Net.BIP;

namespace Keysmith.Net.Bench;
[MemoryDiagnoser]
[ShortRunJob]
public class BIP32Benchmarks
{
    private readonly byte[] _keyBuffer = new byte[32];
    private readonly byte[] _chainCodeBuffer = new byte[32];

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_BIP32_Ethereum_12_Words()
        => BIP32.DerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_12_Words,
            "m/44'/60'/0'/0/0"
        );

    [Benchmark]
    public bool Keysmith_Span_BIP32_Ethereum_12_Words()
    {
        Span<uint> path = stackalloc uint[5];
        BIP44.Ethereum(path);
        return BIP32.TryDerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_12_Words,
            _keyBuffer,
            _chainCodeBuffer,
            path
        );
    }

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_BIP32_Ethereum_18_Words()
        => BIP32.DerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_18_Words,
            "m/44'/60'/0'/0/0"
        );

    [Benchmark]
    public bool Keysmith_Span_BIP32_Ethereum_18_Words()
    {
        Span<uint> path = stackalloc uint[5];
        BIP44.Ethereum(path);
        return BIP32.TryDerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_18_Words,
            _keyBuffer,
            _chainCodeBuffer,
            path
        );
    }

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_BIP32_Ethereum_24_Words()
        => BIP32.DerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_24_Words,
            "m/44'/60'/0'/0/0"
        );

    [Benchmark]
    public bool Keysmith_Span_BIP32_Ethereum_24_Words()
    {
        Span<uint> path = stackalloc uint[5];
        BIP44.Ethereum(path);
        return BIP32.TryDerivePath(
            BIPCurves.Secp256k1,
            TestData.Seed_24_Words,
            _keyBuffer,
            _chainCodeBuffer,
            path
        );
    }
}

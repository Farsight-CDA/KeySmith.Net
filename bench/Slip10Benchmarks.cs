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

    private readonly string _ethereumPath = BIP44.Ethereum();
    private readonly string _solanaPath = BIP44.Solana();

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_Slip10_Secp256k1_Ethereum_512B()
        => Slip10.DerivePath(
            Secp256k1.Instance,
            TestData.Seed_512B,
            _ethereumPath
        );

    [Benchmark]
    public bool Keysmith_Span_Slip10_Secp256k1_Ethereum_512B()
        => Slip10.TryDerivePath(
            Secp256k1.Instance,
            TestData.Seed_512B,
            _keyBuffer,
            _chainCodeBuffer,
            _ethereumPath
        );

    [Benchmark]
    public (byte[], byte[]) Keysmith_Array_Slip10_ED25519_Solana_512B()
        => Slip10.DerivePath(
            ED25519.Instance,
            TestData.Seed_512B,
            _solanaPath
        );

    [Benchmark]
    public bool Keysmith_Span_Slip10_ED25519_Solana_512B()
        => Slip10.TryDerivePath(
            ED25519.Instance,
            TestData.Seed_512B,
            _keyBuffer,
            _chainCodeBuffer,
            _solanaPath
        );
}

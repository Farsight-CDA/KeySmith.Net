using BenchmarkDotNet.Attributes;
using Keysmith.Net.BIP;

namespace Keysmith.Net.Bench;
[MemoryDiagnoser]
[ShortRunJob]
public class BIP39Benchmarks
{
    private readonly byte[] _buffer = new byte[64];

    [Benchmark]
    public byte[] Keysmith_Array_BIP39_12_Words()
        => BIP39.MnemonicToSeed(TestData.Mnemonics_12_Words);

    [Benchmark]
    public bool Keysmith_Span_BIP39_12_Words()
        => BIP39.TryMnemonicToSeed(_buffer, TestData.Mnemonics_12_Words);

    [Benchmark]
    public byte[] Keysmith_Array_BIP39_18_Words()
        => BIP39.MnemonicToSeed(TestData.Mnemonics_18_Words);

    [Benchmark]
    public bool Keysmith_Span_BIP39_18_Words()
        => BIP39.TryMnemonicToSeed(_buffer, TestData.Mnemonics_18_Words);

    [Benchmark]
    public byte[] Keysmith_Array_BIP39_24_Words()
        => BIP39.MnemonicToSeed(TestData.Mnemonics_24_Words);

    [Benchmark]
    public bool Keysmith_Span_BIP39_24_Words()
        => BIP39.TryMnemonicToSeed(_buffer, TestData.Mnemonics_24_Words);
}

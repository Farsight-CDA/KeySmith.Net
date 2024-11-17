using System.Numerics;

namespace Keysmith.Net.BIP.Curves;
internal sealed class ED25519 : BIP32Curve
{
    private const string _ed25519NHex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED";
    private static readonly byte[] _ed25519NBytes = Convert.FromHexString(_ed25519NHex);
    private static readonly BigInteger _ed25519N = new BigInteger(_ed25519NBytes, true, true);

    protected override string Name => "ed25519 seed";
    protected override BigInteger N => _ed25519N;
    protected override ReadOnlySpan<byte> NBytes => _ed25519NBytes;

    protected override void SerializedPoint(Span<byte> point, Span<byte> destination)
        => throw new NotImplementedException();
}
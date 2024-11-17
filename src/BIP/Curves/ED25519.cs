using System.Numerics;

namespace Keysmith.Net.BIP.Curves;
/// <summary>
/// <see href="https://neuromancer.sk/std/other/Ed25519" />
/// </summary>
public sealed class ED25519 : BIPCurve
{
    private const string _ed25519NHex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED";
    private static readonly byte[] _ed25519NBytes = Convert.FromHexString(_ed25519NHex);
    private static readonly BigInteger _ed25519N = new BigInteger(_ed25519NBytes, true, true);

    /// <inheritdoc/>
    public override string Name => "ed25519 seed";
    /// <inheritdoc/>
    public override BigInteger N => _ed25519N;
    /// <inheritdoc/>
    public override ReadOnlySpan<byte> NBytes => _ed25519NBytes;
    /// <inheritdoc/>
    public override void SerializedPoint(Span<byte> point, Span<byte> destination)
        => throw new NotImplementedException();
}
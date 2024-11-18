using System.Numerics;

namespace Keysmith.Net.EC;
/// <summary>
/// <see href="https://neuromancer.sk/std/secg/secp256k1" />
/// </summary>
public sealed class Secp256k1 : ECCurve
{
    /// <summary>
    /// Singleton instance of the Secp256k1 elliptic curve.
    /// </summary>
    public static readonly Secp256k1 Instance = new Secp256k1();
    private static readonly Secp256k1Net.Secp256k1 _secp256k1 = new Secp256k1Net.Secp256k1();

    private static readonly byte[] _nBytes = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static readonly BigInteger _n = new BigInteger(_nBytes, true, true);

    /// <inheritdoc/>
    public override BigInteger N => _n;
    /// <inheritdoc/>
    public override ReadOnlySpan<byte> NBytes => _nBytes;
    /// <inheritdoc/>
    protected override ReadOnlySpan<byte> NameBytes => "Bitcoin seed"u8;

    private Secp256k1() { }

    /// <inheritdoc/>
    public override void MakePublicKey(Span<byte> point, Span<byte> destination)
    {
        Span<byte> publicKeyBuffer = stackalloc byte[64];

        if(!_secp256k1.PublicKeyCreate(publicKeyBuffer, point))
        {
            throw new InvalidOperationException();
        }

        var x = publicKeyBuffer[..32];
        var y = publicKeyBuffer[32..];

        destination[0] = (byte) (y[0] % 2 == 0 ? 0x02 : 0x03);

        x.CopyTo(destination[1..]);
        destination[1..].Reverse();
    }
}

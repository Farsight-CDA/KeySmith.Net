using Secp256k1Net;
using System.Numerics;

namespace Keysmith.Net.BIP.Curves;
internal sealed class Secp256K1 : BIP32Curve
{
    private const string _secp256k1NHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    private static readonly byte[] _secp256k1NBytes = Convert.FromHexString(_secp256k1NHex);
    private static readonly BigInteger _secp256k1N = new BigInteger(_secp256k1NBytes, true, true);

    private static readonly Secp256k1 _secp256k1 = new Secp256k1();

    protected override string Name => "Bitcoin seed";
    protected override BigInteger N => _secp256k1N;
    protected override ReadOnlySpan<byte> NBytes => _secp256k1NBytes;

    protected override void SerializedPoint(Span<byte> point, Span<byte> destination)
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

using Keysmith.Net.EC;
using Keysmith.Net.ED;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Tests;
public class Slip10Tests
{
    [Theory]
    [MemberData(nameof(Slip10TestVectors.Secp256k1), MemberType = typeof(Slip10TestVectors))]
    public void Secp256k1_Should_DeriveCorrectKeys_UsingTestVectors(Slip10TestVector testVector)
    {
        var (privateKey, chainCode) = Slip10.DerivePath(
            Secp256k1.Instance,
            testVector.Seed,
            testVector.DerivationPath
        );

        Span<byte> publicKey = stackalloc byte[Secp256k1.Instance.CompressedPublicKeyLength];
        Secp256k1.Instance.MakeCompressedPublicKey(privateKey, publicKey);

        Assert.Equal(
            testVector.ChainCode, chainCode
        );
        Assert.Equal(
            testVector.PrivateKey, privateKey
        );
        Assert.Equal(
            testVector.PublicKey, publicKey
        );
    }

    [Theory]
    [MemberData(nameof(Slip10TestVectors.ED25519), MemberType = typeof(Slip10TestVectors))]
    public void ED25519_Should_DeriveCorrectKeys_UsingTestVectors(Slip10TestVector testVector)
    {
        var (privateKey, chainCode) = Slip10.DerivePath(
            ED25519.Instance,
            testVector.Seed,
            testVector.DerivationPath
        );

        Span<byte> publicKey = stackalloc byte[ED25519.Instance.PublicKeyLength];
        ED25519.Instance.MakePublicKey(privateKey, publicKey);

        Assert.Equal(
            testVector.ChainCode, chainCode
        );
        Assert.Equal(
            testVector.PrivateKey, privateKey
        );
        Assert.Equal(
            testVector.PublicKey, publicKey
        );
    }
}

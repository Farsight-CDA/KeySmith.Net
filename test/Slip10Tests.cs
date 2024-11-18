using Keysmith.Net.EC;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Tests;
public class Slip10Tests
{
    [Theory]
    [MemberData(nameof(Slip10TestVectors.Secp256k1), MemberType = typeof(Slip10TestVectors))]
    public void Secp256k1_Should_DeriveCorrectKeys_UsingTestVectors(Slip10TestVector testVector)
    {
        var (key, chainCode) = Slip10.DerivePath(
            Secp256k1.Instance,
            testVector.Seed,
            testVector.DerivationPath
        );

        Assert.Equal(
            testVector.ChainCode, chainCode
        );
        Assert.Equal(
            testVector.PrivateKey, key
        );
    }
}

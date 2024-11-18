using Keysmith.Net.EC;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Tests;
public class Slip10Tests
{
    [Fact]
    public void Should_Derive_Correct_Key()
    {
        var (key, _) = Slip10.DerivePath(
            Secp256k1.Instance,
            Convert.FromHexString("354C22AEDB9A37407ADC61F657A6F00D10ED125EFA360215F36C6919ABD94D6DBC193A5F9C495E21EE74118661E327E84A5F5F11FA373EC33B80897D4697557D"),
            $"m/44'/60'/0'/0/0"
        );

        Assert.Equal("ab4accc9310d90a61fc354d8f353bca4a2b3c0590685d3eb82d0216af3badddc", Convert.ToHexString(key), ignoreCase: true);
    }
}

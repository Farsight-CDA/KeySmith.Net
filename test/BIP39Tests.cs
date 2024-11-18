using Keysmith.Net.BIP;

namespace Keysmith.Net.Tests;
public class BIP39Tests
{
    private const string _mnemonic = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";

    [Fact]
    public void Should_Derive_Correct_Key()
    {
        byte[] seed = BIP39.MnemonicToSeed(_mnemonic);
        Assert.Equal(
            "354C22AEDB9A37407ADC61F657A6F00D10ED125EFA360215F36C6919ABD94D6DBC193A5F9C495E21EE74118661E327E84A5F5F11FA373EC33B80897D4697557D",
            Convert.ToHexString(seed)
        );
    }
}

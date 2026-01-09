using Keysmith.Net.BIP;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Tests;

public class BIP44Tests
{
    [Theory]
    [InlineData("m/44'/60'/0'/0/0", new uint[] { 44 + Slip10.HardenedOffset, 60 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset, 0, 0 })]
    [InlineData("m/44'/0'/0'/0/0", new uint[] { 44 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset, 0, 0 })]
    [InlineData("m/44'/1'/0'/0/0", new uint[] { 44 + Slip10.HardenedOffset, 1 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset, 0, 0 })]
    [InlineData("m/44'/501'/0'/0'", new uint[] { 44 + Slip10.HardenedOffset, 501 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset, 0 + Slip10.HardenedOffset })]
    [InlineData("m/0/1/2/3/4", new uint[] { 0, 1, 2, 3, 4 })]
    [InlineData("m/0h/1h/2h", new uint[] { 0 + Slip10.HardenedOffset, 1 + Slip10.HardenedOffset, 2 + Slip10.HardenedOffset })]
    [InlineData("m", new uint[] { })]
    public void Parse_Path_Should_Return_Correct_Indexes(string path, uint[] expected)
    {
        uint[] actual = BIP44.Parse(path);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("")]
    [InlineData("n/44'/60'/0'/0/0")]
    [InlineData("m/")]
    [InlineData("m//")]
    [InlineData("m/invalid")]
    [InlineData("m/2147483648")] // Exceeds uint.MaxValue / 2 (HardenedOffset)
    public void Parse_Path_Should_Throw_On_Invalid_Path(string path)
        => Assert.Throws<ArgumentException>(() => BIP44.Parse(path));

    [Theory]
    [InlineData("m/44'/60'/0'/0/0", 5)]
    [InlineData("m/0/1/2", 3)]
    [InlineData("m", 0)]
    public void Parse_To_Destination_Should_Succeed(string path, int expectedLength)
    {
        Span<uint> destination = new uint[expectedLength];
        BIP44.Parse(path, destination, out int bytesWritten);

        Assert.Equal(expectedLength, bytesWritten);
        uint[] expected = BIP44.Parse(path);
        for(int i = 0; i < expectedLength; i++)
        {
            Assert.Equal(expected[i], destination[i]);
        }
    }

    [Fact]
    public void Parse_To_Destination_Should_Throw_If_Destination_Too_Short()
    {
        string path = "m/44'/60'/0'/0/0";
        uint[] destinationArray = new uint[4];
        Span<uint> destination = destinationArray;
        Assert.Throws<InvalidOperationException>(() => BIP44.Parse(path, destinationArray, out _));
    }

    [Fact]
    public void Parse_To_Destination_Should_Throw_If_Destination_Too_Long()
    {
        string path = "m/44'/60'/0'/0/0";
        uint[] destinationArray = new uint[6];
        Span<uint> destination = destinationArray;
        Assert.Throws<InvalidOperationException>(() => BIP44.Parse(path, destinationArray, out _));
    }

    [Theory]
    [InlineData("m/44'/60'/0'/0/0", true)]
    [InlineData("m/0/1/2", true)]
    [InlineData("m", true)]
    [InlineData("n/44'/60'/0'/0/0", false)]
    [InlineData("m/invalid", false)]
    public void TryParse_Should_Return_Expected_Result(string path, bool expectedSuccess)
    {
        int pathLength = path == "m" ? 0 : path.Split('/').Length - 1;
        Span<uint> destination = new uint[pathLength];
        bool success = BIP44.TryParse(path, destination, out int bytesWritten);

        Assert.Equal(expectedSuccess, success);
        if(expectedSuccess)
        {
            Assert.Equal(pathLength, bytesWritten);
        }
    }

    [Fact]
    public void TryParse_Should_Return_False_If_Destination_Too_Short()
    {
        string path = "m/44'/60'/0'/0/0";
        Span<uint> destination = new uint[4];
        bool success = BIP44.TryParse(path, destination, out _);
        Assert.False(success);
    }
}

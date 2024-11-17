using System.Numerics;
using System.Security.Cryptography;

namespace Keysmith.Net.BIP.Curves;
public abstract partial class BIPCurve
{
    private void GetChildKeyDerivation(Span<byte> currentKey, Span<byte> currentChainCode, uint index)
    {
        Span<byte> dataBuffer = stackalloc byte[currentKey.Length + 5];
        Span<byte> digest = stackalloc byte[64];

        if(index < BIP32.HardenedOffset)
        {
            SerializedPoint(currentKey, dataBuffer[..^4]);
        }
        else
        {
            currentKey.CopyTo(dataBuffer[1..]);
        }

        _ = BitConverter.TryWriteBytes(dataBuffer[^4..], index);
        if(BitConverter.IsLittleEndian)
        {
            dataBuffer[^4..].Reverse();
        }

        _ = HMACSHA512.HashData(currentChainCode, dataBuffer, digest);

        var il = digest[..32];
        var ir = digest[32..];

        var ilNum = new BigInteger(il, isUnsigned: true, isBigEndian: true);
        var keyNum = new BigInteger(currentKey, isUnsigned: true, isBigEndian: true);

        var returnChildKeyNum = (ilNum + keyNum) % N;
        var returnChildKey = il; //Do Not Access il after this
        _ = returnChildKeyNum.TryWriteBytes(returnChildKey, out _, isUnsigned: true, isBigEndian: true);

        if(!IsValidKey(returnChildKey))
        {
            throw new NotSupportedException("Invalid key, try different derivation path");
        }

        returnChildKey.CopyTo(currentKey);
        ir.CopyTo(currentChainCode);
    }
}

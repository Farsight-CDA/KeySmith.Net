using Keysmith.Net.SLIP;
using System.Security.Cryptography;

namespace Keysmith.Net.EC;
/// <summary>
/// Represents an edwards curve.
/// </summary>
public abstract class EDCurve : Slip10Curve
{
    internal override void GetMasterKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination)
    {
        Span<byte> buffer = stackalloc byte[64];

        _ = HMACSHA512.HashData(NameBytes, seed, buffer);

        var il = buffer[..32];
        var ir = buffer[32..];

        il.CopyTo(keyDestination);
        ir.CopyTo(chainCodeDestination);
    }

    internal override void GetChildKeyDerivation(Span<byte> currentKey, Span<byte> currentChainCode, uint index)
    {
        Span<byte> dataBuffer = stackalloc byte[37];

        if(index < Slip10.HardenedOffset)
        {
            throw new NotSupportedException("Edwards curves do not support derivation paths with un-hardened elements");
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

        Span<byte> digest = stackalloc byte[64];
        _ = HMACSHA512.HashData(currentChainCode, dataBuffer, digest);

        digest[..32].CopyTo(currentKey);
        digest[32..].CopyTo(currentChainCode);
    }
}

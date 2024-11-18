using Keysmith.Net.SLIP;
using System.Numerics;
using System.Security.Cryptography;

namespace Keysmith.Net.EC;
/// <summary>
/// Represents an elliptic curve.
/// </summary>
public abstract class ECCurve : Slip10Curve
{
    /// <summary>
    /// The N parameter of the ECCurve.
    /// </summary>
    public abstract BigInteger N { get; }

    /// <summary>
    /// The big-endian encoded bytes of the N parameter of the ECCurve.
    /// </summary>
    public abstract ReadOnlySpan<byte> NBytes { get; }

    /// <summary>
    /// Multiplies the given point with the base point of the curve and serializes it into the given destination span.
    /// </summary>
    /// <param name="point"></param>
    /// <param name="destination"></param>
    public abstract void SerializedPoint(Span<byte> point, Span<byte> destination);

    /// <summary>
    /// Validates if the given key is valid for this ECCurve.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    public bool IsValidPrivateKey(BigInteger key)
        => key < N && key != 0;

    /// <summary>
    /// Validates if the given key is valid for this ECCurve.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    public bool IsValidPrivateKey(ReadOnlySpan<byte> key)
    {
        if(key.Length != NBytes.Length)
        {
            return false;
        }
        if(key.IndexOfAnyExcept((byte) 0) == -1)
        {
            return false;
        }

        for(int i = 0; i < key.Length; i++)
        {
            if(NBytes[i] > key[i])
            {
                return true;
            }
            else if(key[i] > NBytes[i])
            {
                return false;
            }
        }

        return false;
    }

    internal override void GetMasterKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination)
    {
        Span<byte> buffer = stackalloc byte[64];

        _ = HMACSHA512.HashData(NameBytes, seed, buffer);

        var il = buffer[..32];
        var ir = buffer[32..];

        if(!IsValidPrivateKey(il))
        {
            GetMasterKeyFromSeed(buffer, il, ir);
        }

        il.CopyTo(keyDestination);
        ir.CopyTo(chainCodeDestination);
    }

    internal override void GetChildKeyDerivation(Span<byte> currentKey, Span<byte> currentChainCode, uint index)
    {
        Span<byte> dataBuffer = stackalloc byte[37];

        if(index < Slip10.HardenedOffset)
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

        var currentKeyNum = new BigInteger(currentKey, isUnsigned: true, isBigEndian: true);
        BigInteger newKeyNum = 0;

        Span<byte> digest = stackalloc byte[64];

        var il = digest[..32];
        var newChainCode = digest[32..];

        while(true)
        {
            _ = HMACSHA512.HashData(currentChainCode, dataBuffer, digest);

            var ilNum = new BigInteger(il, isUnsigned: true, isBigEndian: true);
            newKeyNum = (ilNum + currentKeyNum) % N;

            if(IsValidPrivateKey(newKeyNum))
            {
                break;
            }

            dataBuffer[0] = 1;
            newChainCode.CopyTo(dataBuffer[1..]);
        }

        _ = newKeyNum.TryWriteBytes(currentKey, out _, isUnsigned: true, isBigEndian: true);
        newChainCode.CopyTo(currentChainCode);
    }
}

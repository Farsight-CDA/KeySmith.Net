using Keysmith.Net.SLIP;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keysmith.Net.EC;
/// <summary>
/// Represents an edwards curve.
/// </summary>
public abstract class EdwardCurve : ECCurve
{
    /// <summary>
    /// Gets the number of bytes that makes up a public key on this curve.
    /// </summary>
    public abstract int PublicKeyLength { get; }

    /// <summary>
    /// Gets the number of bytes that makes up a signature on this curve.
    /// </summary>
    public abstract int SignatureLength { get; }

    /// <summary>
    /// Creates a public key using the private key on this curve and writes it to a given destination buffer.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="destination"></param>
    public abstract void MakePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination);

    /// <summary>
    /// Signs data using the given private key and writes it to the given destination.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    public void Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if(destination.Length != SignatureLength)
        {
            throw new ArgumentException($"Invalid destination length, has to be {SignatureLength} bytes", nameof(destination));
        }

        SignInner(privateKey, data, destination);
    }

    ///
    protected abstract void SignInner(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination);

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

        BinaryPrimitives.WriteUInt32BigEndian(dataBuffer[^4..], index);

        Span<byte> digest = stackalloc byte[64];
        _ = HMACSHA512.HashData(currentChainCode, dataBuffer, digest);

        digest[..32].CopyTo(currentKey);
        digest[32..].CopyTo(currentChainCode);
    }
}

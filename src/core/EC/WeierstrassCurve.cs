using Keysmith.Net.SLIP;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Keysmith.Net.EC;
/// <summary>
/// Represents an elliptic curve.
/// </summary>
public abstract class WeierstrassCurve : ECCurve
{
    /// <summary>
    /// Gets the number of bytes that makes up an uncompressed public key on this curve.
    /// </summary>
    public abstract int UncompressedPublicKeyLength { get; }

    /// <summary>
    /// Gets the number of bytes that makes up a compressed public key on this curve.
    /// </summary>
    public abstract int CompressedPublicKeyLength { get; }

    /// <summary>
    /// Gets the number of bytes that makes up a non-recoverable signature on this curve.
    /// </summary>
    public abstract int NonRecoverableSignatureLength { get; }

    /// <summary>
    /// Gets the number of bytes that makes up a recoverable signature on this curve.
    /// </summary>
    public abstract int RecoverableSignatureLength { get; }

    /// <summary>
    /// The N parameter of the ECCurve.
    /// </summary>
    public abstract BigInteger N { get; }

    /// <summary>
    /// The big-endian encoded bytes of the N parameter of the ECCurve.
    /// </summary>
    public abstract ReadOnlySpan<byte> NBytes { get; }

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

    /// <summary>
    /// Creates a compressed public key using the private key on this curve and writes it to a given destination buffer.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="destination"></param>
    public abstract void MakeCompressedPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination);

    /// <summary>
    /// Creates an uncompressed public key using the private key on this curve and writes it to a given destination buffer.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="destination"></param>
    public abstract void MakeUncompressedPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination);

    /// <summary>
    /// Signs data using the given private key and writes it to the given destination.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    public void Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if(destination.Length != NonRecoverableSignatureLength)
        {
            throw new ArgumentException($"Invalid destination length, has to be {NonRecoverableSignatureLength} bytes", nameof(destination));
        }

        SignInner(privateKey, data, destination, false);
    }

    /// <summary>
    /// Signs data using the given private key and writes it to the given destination.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    public void SignRecoverable(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if(destination.Length != RecoverableSignatureLength)
        {
            throw new ArgumentException($"Invalid destination length, has to be {RecoverableSignatureLength} bytes", nameof(destination));
        }

        SignInner(privateKey, data, destination, true);
    }

    ///
    protected abstract void SignInner(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination, bool recoverable);

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
            MakeCompressedPublicKey(currentKey, dataBuffer[..^4]);
        }
        else
        {
            currentKey.CopyTo(dataBuffer[1..]);
        }

        BinaryPrimitives.WriteUInt32BigEndian(dataBuffer[^4..], index);

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

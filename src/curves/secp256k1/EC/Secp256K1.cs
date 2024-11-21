using System.Numerics;
using System.Runtime.InteropServices;

namespace Keysmith.Net.EC;
/// <summary>
/// <see href="https://neuromancer.sk/std/secg/secp256k1" />
/// </summary>
public sealed class Secp256k1 : WeierstrassCurve
{
    /// <summary>
    /// Singleton instance of the Secp256k1 elliptic curve.
    /// </summary>
    public static readonly Secp256k1 Instance = new Secp256k1();
    private static readonly Secp256k1Net.Secp256k1 _secp256k1 = new Secp256k1Net.Secp256k1();

    private static readonly byte[] _nBytes = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static readonly BigInteger _n = new BigInteger(_nBytes, true, true);

    /// <inheritdoc/>
    public override int UncompressedPublicKeyLength => Secp256k1Net.Secp256k1.PUBKEY_LENGTH;
    /// <inheritdoc/>
    public override int CompressedPublicKeyLength => Secp256k1Net.Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH;
    /// <inheritdoc/>
    public override int NonRecoverableSignatureLength => Secp256k1Net.Secp256k1.SERIALIZED_SIGNATURE_SIZE;
    /// <inheritdoc/>
    public override int RecoverableSignatureLength => Secp256k1Net.Secp256k1.UNSERIALIZED_SIGNATURE_SIZE;

    /// <inheritdoc/>
    public override BigInteger N => _n;
    /// <inheritdoc/>
    public override ReadOnlySpan<byte> NBytes => _nBytes;
    /// <inheritdoc/>
    protected override ReadOnlySpan<byte> NameBytes => "Bitcoin seed"u8;

    private Secp256k1() { }
    /// <inheritdoc/>
    public override void MakeCompressedPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination)
    {
        if(destination.Length != CompressedPublicKeyLength)
        {
            throw new ArgumentException($"Invalid destination length, has to be {CompressedPublicKeyLength} bytes", nameof(destination));
        }

        var mutablePrivateKey = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(privateKey), privateKey.Length);
        Span<byte> publicKeyBuffer = stackalloc byte[64];

        if(!_secp256k1.PublicKeyCreate(publicKeyBuffer, mutablePrivateKey))
        {
            throw new InvalidOperationException();
        }

        var x = publicKeyBuffer[..32];
        var y = publicKeyBuffer[32..];

        destination[0] = (byte) (y[0] % 2 == 0 ? 0x02 : 0x03);

        x.CopyTo(destination[1..]);
        destination[1..].Reverse();
    }
    /// <inheritdoc/>
    public override void MakeUncompressedPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination)
    {
        if(destination.Length != UncompressedPublicKeyLength)
        {
            throw new ArgumentException($"Invalid destination length, has to be {UncompressedPublicKeyLength} bytes", nameof(destination));
        }

        var mutablePrivateKey = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(privateKey), privateKey.Length);

        if(!_secp256k1.PublicKeyCreate(destination, mutablePrivateKey))
        {
            throw new InvalidOperationException();
        }

        if(BitConverter.IsLittleEndian)
        {
            destination[0..32].Reverse();
            destination[32..].Reverse();
        }
    }

    /// <summary>
    /// Signs data using the given private key and writes it to the given destination.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    /// <param name="recoverable"></param>
    protected override void SignInner(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination, bool recoverable)
    {
        var mutablePrivateKey = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(privateKey), privateKey.Length);
        var mutableData = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(data), data.Length);

        if(recoverable)
        {
            if(destination.Length != RecoverableSignatureLength)
            {
                throw new ArgumentException($"Invalid destination length, has to be {RecoverableSignatureLength} bytes", nameof(destination));
            }

            if(!_secp256k1.SignRecoverable(destination, mutableData, mutablePrivateKey))
            {
                throw new NotSupportedException("Signing with secp256k1 failed");
            }
        }
        else
        {
            if(destination.Length != NonRecoverableSignatureLength)
            {
                throw new ArgumentException($"Invalid destination length, has to be {NonRecoverableSignatureLength} bytes", nameof(destination));
            }

            if(!_secp256k1.Sign(destination, mutableData, mutablePrivateKey))
            {
                throw new NotSupportedException("Signing with secp256k1 failed");
            }
        }
    }

    /// <inheritdoc/>
    public override bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var mutablePublicKey = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(publicKey), publicKey.Length);
        var mutableData = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(data), data.Length);
        var mutableSignature = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(signature), signature.Length);

        return _secp256k1.Verify(mutableSignature, mutableData, mutablePublicKey);
    }
}

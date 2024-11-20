using Keysmith.Net.EC;
using NSec.Cryptography;

namespace Keysmith.Net.ED;
/// <summary>
/// <see href="https://neuromancer.sk/std/other/Ed25519" />
/// </summary>
public class ED25519 : EDCurve
{
    /// <summary>
    /// Singleton instance of the ED25519 elliptic curve.
    /// </summary>
    public static readonly ED25519 Instance = new ED25519();

    /// <inheritdoc />
    public override int PublicKeyLength => SignatureAlgorithm.Ed25519.PublicKeySize;
    /// <inheritdoc />
    public override int SignatureLength => SignatureAlgorithm.Ed25519.SignatureSize;

    /// <inheritdoc />
    protected override ReadOnlySpan<byte> NameBytes => "ed25519 seed"u8;
    /// <inheritdoc />
    public override void MakePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination)
    {
        Key key = null!;

        try
        {
            if(!Key.TryImport(SignatureAlgorithm.Ed25519, privateKey, KeyBlobFormat.RawPrivateKey, out key!))
            {
                throw new NotSupportedException();
            }

            if(!key.PublicKey.TryExport(KeyBlobFormat.RawPublicKey, destination, out _))
            {
                throw new NotSupportedException();
            }
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <inheritdoc />
    protected override void SignInner(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Key key = null!;

        try
        {
            if(!Key.TryImport(SignatureAlgorithm.Ed25519, privateKey, KeyBlobFormat.RawPrivateKey, out key!))
            {
                throw new NotSupportedException();
            }

            SignatureAlgorithm.Ed25519.Sign(key, data, destination);
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <inheritdoc />
    public override bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if(!PublicKey.TryImport(SignatureAlgorithm.Ed25519, publicKey, KeyBlobFormat.RawPublicKey, out var key!))
        {
            throw new NotSupportedException();
        }
        //
        return SignatureAlgorithm.Ed25519.Verify(key, data, signature);
    }

}

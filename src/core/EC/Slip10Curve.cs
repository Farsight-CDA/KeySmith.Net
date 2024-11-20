namespace Keysmith.Net.EC;
/// <summary>
/// Represents a curve that is supported by the Slip10 standard.
/// </summary>
public abstract class Slip10Curve
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
    /// Ascii encoded bytes of the elliptic curve name to be used for master key derivation.
    /// </summary>
    protected abstract ReadOnlySpan<byte> NameBytes { get; }

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
    /// <summary>
    /// Verify if the given signature is valid on the given data.
    /// </summary>
    /// <param name="publicKey"></param>
    /// <param name="data"></param>
    /// <param name="signature"></param>
    public abstract bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    internal abstract void GetMasterKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination);
    internal abstract void GetChildKeyDerivation(Span<byte> currentKey, Span<byte> currentChainCode, uint index);

    ///
    protected abstract void SignInner(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, Span<byte> destination);

    internal void DerivePath(ReadOnlySpan<byte> seed,
        Span<byte> keyDestination, Span<byte> chainCodeDestination,
        params ReadOnlySpan<uint> path)
    {
        GetMasterKeyFromSeed(seed, keyDestination, chainCodeDestination);

        foreach(uint derivStep in path)
        {
            GetChildKeyDerivation(keyDestination, chainCodeDestination, derivStep);
        }
    }
}

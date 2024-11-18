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
    /// Ascii encoded bytes of the elliptic curve name to be used for master key derivation.
    /// </summary>
    protected abstract ReadOnlySpan<byte> NameBytes { get; }

    /// <summary>
    /// Creates a public key using the private key on this curve and writes it to a given destination buffer.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="destination"></param>
    public abstract void MakePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> destination);

    internal abstract void GetMasterKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination);
    internal abstract void GetChildKeyDerivation(Span<byte> currentKey, Span<byte> currentChainCode, uint index);

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

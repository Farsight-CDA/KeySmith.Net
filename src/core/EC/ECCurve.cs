namespace Keysmith.Net.EC;
/// <summary>
/// Represents a curve that is supported by the Slip10 standard.
/// </summary>
public abstract class ECCurve
{
    /// <summary>
    /// Ascii encoded bytes of the elliptic curve name to be used for master key derivation.
    /// </summary>
    protected abstract ReadOnlySpan<byte> NameBytes { get; }

    /// <summary>
    /// Verify if the given signature is valid on the given data.
    /// </summary>
    /// <param name="publicKey"></param>
    /// <param name="data"></param>
    /// <param name="signature"></param>
    public abstract bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

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

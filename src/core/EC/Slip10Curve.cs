using Keysmith.Net.SLIP;

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

    internal void DerivePath(ReadOnlySpan<byte> seed,
        Span<byte> keyDestination, Span<byte> chainCodeDestination,
        ReadOnlySpan<char> path)
    {
        if(path.Length == 0 || path[0] != 'm')
        {
            throw new ArgumentException("Invalid derivation path", nameof(path));
        }
        if(path.Length > 1 && path[1] != '/')
        {
            throw new ArgumentException("Invalid derivation path", nameof(path));
        }

        int pathLength = path.Count('/');
        var subPath = path[1..];

        Span<uint> pathBuffer = stackalloc uint[pathLength];

        int pathIndex = -1;
        foreach(var range in subPath.Split('/'))
        {
            var segment = subPath[range];

            if(segment.Length == 0 && pathIndex == -1)
            {
                pathIndex = 0;
                continue;
            }

            bool isHardened = segment[^1] == '\'' || segment[^1] == 'h';

            if(!uint.TryParse(isHardened ? segment[..^1] : segment, out uint derivStep))
            {
                throw new ArgumentException($"Invalid derivation path. Failed to parse at index {pathIndex}", nameof(path));
            }
            if(derivStep >= Slip10.HardenedOffset)
            {
                throw new ArgumentException($"Invalid derivation path. Path to large at index {pathIndex}", nameof(path));
            }

            if(isHardened)
            {
                derivStep = derivStep += Slip10.HardenedOffset;
            }

            pathBuffer[pathIndex] = derivStep;
            pathIndex++;
        }

        DerivePath(seed, keyDestination, chainCodeDestination, pathBuffer);
    }
}

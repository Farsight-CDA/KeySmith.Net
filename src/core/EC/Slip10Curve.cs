using Keysmith.Net.SLIP;

namespace Keysmith.Net.EC;
/// <summary>
/// Represents a curve that is supported by the Slip10 standard.
/// </summary>
public abstract class Slip10Curve
{
    /// <summary>
    /// Ascii encoded bytes of the elliptic curve name to be used for master key derivation.
    /// </summary>
    protected abstract ReadOnlySpan<byte> NameBytes { get; }

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
        string path)
    {
        if(path.Length < 2 || path[0] != 'm' || path[1] != '/')
        {
            throw new ArgumentException("Invalid derivation path", nameof(path));
        }

        var valuePath = path[2..].AsSpan();
        int pathLength = valuePath.Count('/') + 1;

        if(pathLength == 0)
        {
            throw new ArgumentException("Invalid derivation path", nameof(path));
        }

        Span<uint> pathBuffer = stackalloc uint[pathLength];

        int pathIndex = 0;
        foreach(var range in valuePath.Split('/'))
        {
            var segment = valuePath[range];
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

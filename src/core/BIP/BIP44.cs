using Keysmith.Net.SLIP;
using System.Globalization;
using System.Text;

namespace Keysmith.Net.BIP;
/// <summary>
/// Implemenation of common derivation paths used in various ecosystems following the BIP44 spec.
/// <see href="https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki" />
/// </summary>
public static class BIP44
{
    /// <summary>
    /// Constructs a derivation path typically used by EVM chains.
    /// </summary>
    /// <param name="accountIndex"></param>
    /// <returns></returns>
    public static string Ethereum(uint accountIndex = 0)
        => $"m/44'/{(int) Slip44CoinType.Ethereum}'/0'/0/{accountIndex}";

    /// <summary>
    /// Constructs a derivation path typically used by EVM chains and writes it to a provided span.
    /// </summary>
    /// <param name="destination"></param>
    /// <param name="accountIndex"></param>
    public static void Ethereum(Span<uint> destination, uint accountIndex = 0)
        => WriteInto(destination,
            Slip10.HardenedOffset + 44,
            Slip10.HardenedOffset + (uint) Slip44CoinType.Ethereum,
            Slip10.HardenedOffset + 0,
            0,
            accountIndex
        );

    /// <summary>
    /// Constructs a derivation path typically used by Cosmos chains.
    /// </summary>
    /// <param name="accountIndex"></param>
    /// <returns></returns>
    public static string Cosmos(int accountIndex = 0)
        => $"m/44'/{(int) Slip44CoinType.Cosmos}'/0'/0/{accountIndex}";

    /// <summary>
    /// Constructs a derivation path typically used by Cosmos chains and writes it to a provided span.
    /// </summary>
    /// <param name="destination"></param>
    /// <param name="accountIndex"></param>
    public static void Cosmos(Span<uint> destination, uint accountIndex = 0)
        => WriteInto(destination,
            Slip10.HardenedOffset + 44,
            Slip10.HardenedOffset + (uint) Slip44CoinType.Cosmos,
            Slip10.HardenedOffset + 0,
            0,
            accountIndex
        );

    /// <summary>
    /// Constructs a derivation path typically used by Cosmos chains.
    /// </summary>
    /// <param name="accountIndex"></param>
    /// <returns></returns>
    public static string Solana(int accountIndex = 0)
        => $"m/44'/{(int) Slip44CoinType.Solana}'/{accountIndex}'/0'";

    /// <summary>
    /// Constructs a derivation path typically used by Cosmos chains and writes it to a provided span.
    /// </summary>
    /// <param name="destination"></param>
    /// <param name="accountIndex"></param>
    public static void Solana(Span<uint> destination, uint accountIndex = 0)
        => WriteInto(destination,
            Slip10.HardenedOffset + 44,
            Slip10.HardenedOffset + (uint) Slip44CoinType.Solana,
            Slip10.HardenedOffset + accountIndex,
            Slip10.HardenedOffset + 0
        );

    /// <summary>
    /// Creates a BIP44 derivation path string given a span of indexes.
    /// </summary>
    /// <param name="indexes"></param>
    /// <returns></returns>
    public static string MakePath(params ReadOnlySpan<uint> indexes)
    {
        var sb = new StringBuilder("m", indexes.Length * 3);
        foreach(uint index in indexes)
        {
            _ = index < Slip10.HardenedOffset
                ? sb.Append(CultureInfo.InvariantCulture, $"/{index}")
                : sb.Append(CultureInfo.InvariantCulture, $"/{index - Slip10.HardenedOffset}'");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Gets the number of indexes in the given derivation path.
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    public static int GetPathLength(ReadOnlySpan<char> path)
        => path.Count('/');

    /// <summary>
    /// Parses the given derivation path into a uint array. Throws if parsing fails.
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static uint[] Parse(ReadOnlySpan<char> path)
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

        if(pathLength == 0)
        {
            return [];
        }

        uint[] pathBuffer = new uint[pathLength];

        int pathIndex = 0;
        var subPath = path[2..]; // Skip 'm/'
        foreach(var range in subPath.Split('/'))
        {
            var segment = subPath[range];

            if(segment.Length == 0)
            {
                throw new ArgumentException($"Invalid derivation path. Empty segment at index {pathIndex}", nameof(path));
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

            if(pathIndex >= pathBuffer.Length)
            {
                throw new ArgumentException("Invalid derivation path. Path length mismatch.", nameof(path));
            }

            pathBuffer[pathIndex] = derivStep;
            pathIndex++;
        }

        return pathBuffer;
    }

    /// <summary>
    /// Parses the given derivation path into a uint array. Throws if parsing fails.
    /// </summary>
    /// <param name="path"></param>
    /// <param name="destination"></param>
    /// <param name="bytesWritten"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static void Parse(ReadOnlySpan<char> path, Span<uint> destination, out int bytesWritten)
    {
        if(!TryParse(path, destination, out bytesWritten))
        {
            throw new InvalidOperationException("Parsing BIP44 derivation path failed");
        }
    }

    /// <summary>
    /// Parses the given derivation path into a given span of uint. Returns false if parsing fails.
    /// </summary>
    /// <param name="path"></param>
    /// <param name="destination"></param>
    /// <param name="bytesWritten"></param>
    /// <returns></returns>
    public static bool TryParse(ReadOnlySpan<char> path, Span<uint> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if(path.Length == 0 || path[0] != 'm')
        {
            return false;
        }
        if(path.Length > 1 && path[1] != '/')
        {
            return false;
        }

        int pathLength = path.Count('/');

        if(destination.Length != pathLength)
        {
            return false;
        }

        if(pathLength == 0)
        {
            bytesWritten = 0;
            return true;
        }

        var subPath = path[2..];

        int pathIndex = 0;
        foreach(var range in subPath.Split('/'))
        {
            var segment = subPath[range];

            if(segment.Length == 0)
            {
                return false;
            }

            bool isHardened = segment[^1] == '\'' || segment[^1] == 'h';

            if(!uint.TryParse(isHardened ? segment[..^1] : segment, out uint derivStep))
            {
                return false;
            }
            if(derivStep >= Slip10.HardenedOffset)
            {
                return false;
            }

            if(isHardened)
            {
                derivStep = derivStep += Slip10.HardenedOffset;
            }

            destination[pathIndex] = derivStep;
            pathIndex++;
        }

        bytesWritten = pathLength;
        return true;
    }

    private static void WriteInto(Span<uint> destination, params Span<uint> values)
    {
        if(values.Length != destination.Length)
        {
            throw new ArgumentException($"Destination must have a length of {values.Length}.", nameof(destination));
        }

        values.CopyTo(destination);
    }
}

using Keysmith.Net.SLIP;

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
    public static void Cosmos(Span<uint> destination, uint accountIndex)
        => WriteInto(destination,
            Slip10.HardenedOffset + 44,
            Slip10.HardenedOffset + (uint) Slip44CoinType.Cosmos,
            Slip10.HardenedOffset + 0,
            0,
            accountIndex
        );

    private static void WriteInto(Span<uint> destination, params Span<uint> values)
    {
        if(values.Length != destination.Length)
        {
            throw new ArgumentException($"Destionation must have a length of {values.Length}.", nameof(destination));
        }

        values.CopyTo(destination);
    }
}

namespace Keysmith.Net.SLIP;
/// <summary>
/// Coin types registered in the Slip44 standard defined here <see href="https://github.com/satoshilabs/slips/blob/master/slip-0044.md" />
/// </summary>
public enum Slip44CoinType : uint
{
    /// <summary>
    /// BTC
    /// </summary>
    Bitcoin = 0,
    /// <summary>
    /// ETH
    /// </summary>
    Ethereum = 60,
    /// <summary>
    /// ATOM
    /// </summary>
    Cosmos = 118,
    /// <summary>
    /// SOL
    /// </summary>
    Solana = 501,
    /// <summary>
    /// SCRT
    /// </summary>
    SecretNetwork = 529,
    /// <summary>
    /// ADA
    /// </summary>
    Cardano = 1815
}

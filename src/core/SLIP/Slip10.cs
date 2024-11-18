using Keysmith.Net.EC;

namespace Keysmith.Net.SLIP;
/// <summary>
/// Implementation of SLIP10 following this spec
/// <see href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md"/>
/// </summary>
public static class Slip10
{
    /// <summary>
    /// Offset above which elements in a derivation path are considered hardened.
    /// </summary>
    public const uint HardenedOffset = 2147483648u;

    /// <summary>
    /// Derives the master private key based on a seed. 
    /// Implements <see href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md#master-key-generation"/>.
    /// </summary>
    /// <param name="curve">Elliptic Curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <returns>Tuple of derived master key and the corresponding chain code</returns>
    public static (byte[] Key, byte[] ChainCode) DeriveMasterKey(Slip10Curve curve, ReadOnlySpan<byte> seed)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));

        byte[] key = new byte[32];
        byte[] chainCode = new byte[32];
        curve.GetMasterKeyFromSeed(seed, key, chainCode);
        return (key, chainCode);
    }

    /// <summary>
    /// Derives the master private key based on a seed and writes it to a provided buffer. 
    /// Implements <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation"/>.
    /// </summary>
    /// <param name="curve">Elliptic Curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <param name="keyDestination">Span to write the master key to</param>
    /// <param name="chainCodeDestination">Span to write the chain code to</param>
    /// <returns>True if successful, false if not</returns>
    public static bool TryGetMasterKeyFromSeed(Slip10Curve curve, ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination)
    {
        if(curve is null)
        {
            return false;
        }
        if(keyDestination.Length != 32 || chainCodeDestination.Length != 32)
        {
            return false;
        }

        curve.GetMasterKeyFromSeed(seed, keyDestination, chainCodeDestination);
        return true;
    }

    /// <summary>
    /// Derives the master key using the given seed which is than used to derive a child key using the given path.
    /// Implements <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key" />.
    /// </summary>
    /// <param name="curve">Elliptic Curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <param name="path">Raw path to use</param>
    /// <returns>Tuple of derived child key and the corresponding chain code</returns>
    /// <exception cref="ArgumentException"></exception>
    public static (byte[], byte[]) DerivePath(Slip10Curve curve, ReadOnlySpan<byte> seed, params ReadOnlySpan<uint> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        if(path.Length == 0)
        {
            throw new ArgumentException("Path cannot be empty", nameof(path));
        }

        byte[] keyBuffer = new byte[32];
        byte[] chainCodeBuffer = new byte[32];
        curve.DerivePath(seed, keyBuffer, chainCodeBuffer, path);
        return (keyBuffer, chainCodeBuffer);
    }

    /// <summary>
    /// Derives the master key using the given seed which is than used to derive a child key using the given path and writes it to a provided buffer.
    /// Implements <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key" />.
    /// </summary>
    /// <param name="curve">Elliptic curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <param name="keyDestination">Span to write the child key to</param>
    /// <param name="chainCodeDestination">Span to write the chain code to</param>
    /// <param name="path">Raw path to use</param>
    /// <returns></returns>
    public static bool TryDerivePath(Slip10Curve curve, ReadOnlySpan<byte> seed,
        Span<byte> keyDestination, Span<byte> chainCodeDestination, params ReadOnlySpan<uint> path)
    {
        if(curve is null)
        {
            return false;
        }
        if(keyDestination.Length != 32 || chainCodeDestination.Length != 32)
        {
            return false;
        }

        curve.DerivePath(seed, keyDestination, chainCodeDestination, path);
        return true;
    }

    /// <summary>
    /// Derives the master key using the given seed which is than used to derive a child key using the given path.
    /// Implements <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key" />.
    /// </summary>
    /// <param name="curve">Elliptic Curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <param name="path">BIP44 spec derivation path</param>
    /// <returns>Tuple of derived child key and the corresponding chain code</returns>
    /// <exception cref="ArgumentException"></exception>
    public static (byte[], byte[]) DerivePath(Slip10Curve curve, ReadOnlySpan<byte> seed, ReadOnlySpan<char> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));

        byte[] keyBuffer = new byte[32];
        byte[] chainCodeBuffer = new byte[32];
        curve.DerivePath(seed, keyBuffer, chainCodeBuffer, path);
        return (keyBuffer, chainCodeBuffer);
    }

    /// <summary>
    /// Derives the master key using the given seed which is than used to derive a child key using the given path and writes it to a provided buffer.
    /// Implements <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key" />.
    /// </summary>
    /// <param name="curve">Elliptic curve to use</param>
    /// <param name="seed">Seed to base the derivation on</param>
    /// <param name="keyDestination">Span to write the child key to</param>
    /// <param name="chainCodeDestination">Span to write the chain code to</param>
    /// <param name="path">BIP44 spec derivation path</param>
    /// <returns></returns>
    public static bool TryDerivePath(Slip10Curve curve, ReadOnlySpan<byte> seed,
        Span<byte> keyDestination, Span<byte> chainCodeDestination,
        ReadOnlySpan<char> path)
    {
        if(curve is null)
        {
            return false;
        }
        if(keyDestination.Length != 32 || chainCodeDestination.Length != 32)
        {
            return false;
        }

        curve.DerivePath(seed, keyDestination, chainCodeDestination, path);
        return true;
    }
}

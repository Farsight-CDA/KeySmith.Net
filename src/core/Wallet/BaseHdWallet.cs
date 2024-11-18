using Keysmith.Net.BIP;
using Keysmith.Net.EC;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Wallet;
/// <summary>
/// Base class containing blockchain agnostic standards to be inherited by chain specific wallets.
/// </summary>
public abstract class BaseHdWallet
{
    private readonly Slip10Curve _curve;

    /// <summary>
    /// Private key of the wallet.
    /// </summary>
    protected readonly byte[] _privateKey;
    /// <summary>
    /// Public key of the wallet.
    /// </summary>
    protected readonly byte[] _publicKey;
    ///
    protected BaseHdWallet(Slip10Curve curve, ReadOnlySpan<byte> privateKey)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        if(_curve is ECCurve eCCurve && !eCCurve.IsValidPrivateKey(privateKey))
        {
            throw new ArgumentException("Invalid private key", nameof(privateKey));
        }

        _privateKey = privateKey.ToArray();
        _publicKey = new byte[_curve.PublicKeyLength];
        curve.MakePublicKey(_privateKey, _publicKey);
    }
    ///
    protected BaseHdWallet(Slip10Curve curve, ReadOnlySpan<byte> seed, ReadOnlySpan<char> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _publicKey = new byte[_curve.PublicKeyLength];
        curve.MakePublicKey(_privateKey, _publicKey);
    }
    ///
    protected BaseHdWallet(Slip10Curve curve, ReadOnlySpan<byte> seed, params ReadOnlySpan<uint> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _publicKey = new byte[_curve.PublicKeyLength];
        curve.MakePublicKey(_privateKey, _publicKey);
    }
    ///
    protected BaseHdWallet(Slip10Curve curve, string mnemonic, string passphrase, ReadOnlySpan<char> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        Span<byte> seed = stackalloc byte[64];
        if(!BIP39.TryMnemonicToSeed(seed, mnemonic, passphrase))
        {
            throw new ArgumentException("Invalid mnemonics", nameof(mnemonic));
        }

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _publicKey = new byte[_curve.PublicKeyLength];
        curve.MakePublicKey(_privateKey, _publicKey);
    }
    ///
    protected BaseHdWallet(Slip10Curve curve, string mnemonic, string passphrase, params ReadOnlySpan<uint> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        Span<byte> seed = stackalloc byte[64];
        if(!BIP39.TryMnemonicToSeed(seed, mnemonic, passphrase))
        {
            throw new ArgumentException("Invalid mnemonics", nameof(mnemonic));
        }

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _publicKey = new byte[_curve.PublicKeyLength];
        curve.MakePublicKey(_privateKey, _publicKey);
    }
}

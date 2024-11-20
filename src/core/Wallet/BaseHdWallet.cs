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

    /// <summary>
    /// Signs the given message and returns the signature as an array.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        byte[] signature = new byte[_curve.SignatureLength];
        _curve.Sign(_privateKey, data, signature);
        return signature;
    }

    /// <summary>
    /// Signs the given message and writes it to a given destination span.
    /// </summary>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    /// <returns></returns>
    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if(destination.Length != _curve.SignatureLength)
        {
            return false;
        }

        _curve.Sign(_privateKey, data, destination);
        return true;
    }
}

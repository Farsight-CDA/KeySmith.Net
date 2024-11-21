using Keysmith.Net.BIP;
using Keysmith.Net.EC;
using Keysmith.Net.SLIP;

namespace Keysmith.Net.Wallet;
/// <summary>
/// Base class containing blockchain agnostic standards to be inherited by chain specific wallets.
/// </summary>
public abstract class BaseWeierstrassHdWallet<TCurve>
    where TCurve : WeierstrassCurve
{
    /// <summary>
    /// The underlying elliptic curve of the wallet.
    /// </summary>
    protected readonly TCurve _curve;
    /// <summary>
    /// Private key of the wallet.
    /// </summary>
    protected readonly byte[] _privateKey;
    /// <summary>
    /// Compressed public key of the wallet.
    /// </summary>
    protected readonly byte[] _compressedPublicKey;
    /// <summary>
    /// Uncompressed public key of the wallet.
    /// </summary>
    protected readonly byte[] _uncompressedPublicKey;

    ///
    protected BaseWeierstrassHdWallet(TCurve curve, ReadOnlySpan<byte> privateKey)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        _privateKey = privateKey.ToArray();

        _compressedPublicKey = new byte[_curve.CompressedPublicKeyLength];
        _uncompressedPublicKey = new byte[_curve.UncompressedPublicKeyLength];
        curve.MakeCompressedPublicKey(_privateKey, _compressedPublicKey);
        curve.MakeUncompressedPublicKey(_privateKey, _uncompressedPublicKey);
    }
    ///
    protected BaseWeierstrassHdWallet(TCurve curve, ReadOnlySpan<byte> seed, ReadOnlySpan<char> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _compressedPublicKey = new byte[_curve.CompressedPublicKeyLength];
        _uncompressedPublicKey = new byte[_curve.UncompressedPublicKeyLength];
        curve.MakeCompressedPublicKey(_privateKey, _compressedPublicKey);
        curve.MakeUncompressedPublicKey(_privateKey, _uncompressedPublicKey);
    }
    ///
    protected BaseWeierstrassHdWallet(TCurve curve, ReadOnlySpan<byte> seed, params ReadOnlySpan<uint> path)
    {
        ArgumentNullException.ThrowIfNull(curve, nameof(curve));
        _curve = curve;

        _privateKey = new byte[32];
        Span<byte> buffer = stackalloc byte[32];
        if(!Slip10.TryDerivePath(curve, seed, _privateKey, buffer, path))
        {
            throw new ArgumentException("Invalid path", nameof(path));
        }

        _compressedPublicKey = new byte[_curve.CompressedPublicKeyLength];
        _uncompressedPublicKey = new byte[_curve.UncompressedPublicKeyLength];
        curve.MakeCompressedPublicKey(_privateKey, _compressedPublicKey);
        curve.MakeUncompressedPublicKey(_privateKey, _uncompressedPublicKey);
    }
    ///
    protected BaseWeierstrassHdWallet(TCurve curve, string mnemonic, string passphrase, ReadOnlySpan<char> path)
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

        _compressedPublicKey = new byte[_curve.CompressedPublicKeyLength];
        _uncompressedPublicKey = new byte[_curve.UncompressedPublicKeyLength];
        curve.MakeCompressedPublicKey(_privateKey, _compressedPublicKey);
        curve.MakeUncompressedPublicKey(_privateKey, _uncompressedPublicKey);
    }
    ///
    protected BaseWeierstrassHdWallet(TCurve curve, string mnemonic, string passphrase, params ReadOnlySpan<uint> path)
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

        _compressedPublicKey = new byte[_curve.CompressedPublicKeyLength];
        _uncompressedPublicKey = new byte[_curve.UncompressedPublicKeyLength];
        curve.MakeCompressedPublicKey(_privateKey, _compressedPublicKey);
        curve.MakeUncompressedPublicKey(_privateKey, _uncompressedPublicKey);
    }

    /// <summary>
    /// Signs the given message and returns the signature as an array.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        byte[] signature = new byte[_curve.NonRecoverableSignatureLength];
        _curve.Sign(_privateKey, data, signature);
        return signature;
    }

    /// <summary>
    /// Signs the given message and returns the signature as an array.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public byte[] SignRecoverable(ReadOnlySpan<byte> data)
    {
        byte[] signature = new byte[_curve.RecoverableSignatureLength];
        _curve.SignRecoverable(_privateKey, data, signature);
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
        if(destination.Length != _curve.NonRecoverableSignatureLength)
        {
            return false;
        }

        _curve.Sign(_privateKey, data, destination);
        return true;
    }

    /// <summary>
    /// Signs the given message and writes it to a given destination span.
    /// </summary>
    /// <param name="data"></param>
    /// <param name="destination"></param>
    /// <returns></returns>
    public bool TrySignRecoverable(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if(destination.Length != _curve.RecoverableSignatureLength)
        {
            return false;
        }

        _curve.SignRecoverable(_privateKey, data, destination);
        return true;
    }
}

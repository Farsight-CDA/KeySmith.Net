using Keysmith.Net.EC;

namespace Keysmith.Net.Wallet;
/// <summary>
/// Base class containing blockchain agnostic standards to be inherited by chain specific wallets.
/// </summary>
public abstract class BaseHdWallet
{
    private readonly Slip10Curve _curve;

    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;
    private readonly byte[] _address;

    /// <summary>
    /// Private key of the wallet.
    /// </summary>
    public ReadOnlySpan<byte> PrivateKey
        => _privateKey;

    /// <summary>
    /// Public key of the wallet.
    /// </summary>
    public ReadOnlySpan<byte> PublicKey
        => _publicKey;

    /// <summary>
    /// The address of the wallet.
    /// </summary>
    public ReadOnlySpan<byte> Address
        => _address;

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
        curve.MakePublicKey(privateKey, _publicKey);

        _address = new byte[AddressLength];
        CalculateAddress(_address);
    }

    /// <summary>
    /// The byte length of an address.
    /// </summary>
    protected abstract int AddressLength { get; }

    /// <summary>
    /// Calculates the address of the wallet and writes it into the provided destination buffer.
    /// </summary>
    /// <param name="destination"></param>
    protected abstract void CalculateAddress(Span<byte> destination);
}

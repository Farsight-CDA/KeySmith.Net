using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Keysmith.Net.BIP;

/// <summary>
/// Implementation of BIP39 following this spec
/// <see href="https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki"/>
/// </summary>
public static class BIP39
{
    /// <summary>
    /// Converts english mnemonic words into a seed.
    /// </summary>
    /// <param name="mnemonic">mnemonic words</param>
    /// <param name="passphrase">optional passphrase</param>
    /// <returns></returns>
    public static byte[] MnemonicToSeed(string mnemonic, string passphrase = "")
    {
        byte[] buffer = new byte[64];
        _ = TryMnemonicToSeed(buffer, mnemonic, passphrase);
        return buffer;
    }

    /// <summary>
    /// Converts english mnemonic words into a seed and writes it to a given buffer.
    /// </summary>
    /// <param name="destination">Span to write the seed to</param>
    /// <param name="mnemonic">Mnemonic words</param>
    /// <param name="passphrase">Optional passphrase</param>
    /// <returns></returns>
    public static bool TryMnemonicToSeed(Span<byte> destination, string mnemonic, string passphrase = "")
    {
        if(destination.Length != 64 || string.IsNullOrEmpty(mnemonic) || passphrase is null)
        {
            return false;
        }

        string normalizedMnemonic = mnemonic.Normalize(NormalizationForm.FormKD);
        string normalizedSaltedPassword = $"mnemonic{passphrase.Normalize(NormalizationForm.FormKD)}";

        int passwordSize = Encoding.UTF8.GetByteCount(normalizedMnemonic);
        int saltBufferSize = Encoding.UTF8.GetByteCount(normalizedSaltedPassword);

        byte[]? rentedPasswordBuffer = null;
        byte[]? rentedSaltBuffer = null;

        var passwordBuffer = passwordSize > 1024
            ? (rentedPasswordBuffer = ArrayPool<byte>.Shared.Rent(passwordSize)).AsSpan(passwordSize)
            : stackalloc byte[passwordSize];
        var saltBuffer = saltBufferSize > 1024
            ? (rentedSaltBuffer = ArrayPool<byte>.Shared.Rent(saltBufferSize)).AsSpan(passwordSize)
            : stackalloc byte[saltBufferSize];

        try
        {
            _ = Encoding.UTF8.GetBytes(normalizedMnemonic, passwordBuffer);
            _ = Encoding.UTF8.GetBytes(normalizedSaltedPassword, saltBuffer);

            Rfc2898DeriveBytes.Pbkdf2(passwordBuffer, saltBuffer, destination, 2048, HashAlgorithmName.SHA512);
            return true;
        }
        finally
        {
            if(rentedPasswordBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedPasswordBuffer);
            }
            if(rentedSaltBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedSaltBuffer);
            }
        }
    }
}

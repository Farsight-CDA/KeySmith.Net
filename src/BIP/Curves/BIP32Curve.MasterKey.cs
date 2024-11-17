using System.Security.Cryptography;
using System.Text;

namespace Keysmith.Net.BIP.Curves;
internal abstract partial class BIP32Curve
{
    internal void GetMasterKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> keyDestination, Span<byte> chainCodeDestination)
    {
        Span<byte> curveBuffer = stackalloc byte[Encoding.ASCII.GetByteCount(Name)];
        Span<byte> buffer = stackalloc byte[64];

        _ = Encoding.ASCII.GetBytes(Name, curveBuffer);
        _ = HMACSHA512.HashData(curveBuffer, seed, buffer);

        var il = buffer[..32];
        var ir = buffer[32..];

        if(!IsValidKey(il))
        {
            GetMasterKeyFromSeed(buffer, il, ir);
        }

        il.CopyTo(keyDestination);
        ir.CopyTo(chainCodeDestination);
    }
}

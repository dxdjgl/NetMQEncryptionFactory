using System;

namespace NetMQSecurityFactory
{
    public interface ICurveEncrypt : IDisposable
    {
        void SetKey(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey);
        void Encrypt(Span<byte> cipher, Span<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce);
        void Encrypt(Span<byte> cipher, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce);
        bool TryDecrypt(Span<byte> message, ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce);
        bool TryDecrypt(Span<byte> message, ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce);
    }
}

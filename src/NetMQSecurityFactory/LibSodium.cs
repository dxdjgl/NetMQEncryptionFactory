using System;
using System.Runtime.InteropServices;

namespace NetMQSecurityFactory
{
    [EncryptionPriority]
    public class LibSodium : ICurveEncrypt
    {
        private byte[] SharedSecretKey = new byte[32];
        const string DllName = "libsodium.dll";

        //crypto_secretbox_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_easy(ref byte buffer, byte[] message, long messageLength, byte[] nonce, byte[] key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_beforenm(byte[] shared_key, byte[] public_key, byte[] secret_key);

        //crypto_secretbox_open_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_easy(ref byte buffer, byte[] cipherText, long cipherTextLength, byte[] nonce, byte[] key);

        //sodium_version_string
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_version_string();

        public LibSodium()
        {
            var ptr = LibSodium.sodium_version_string();
            Marshal.PtrToStringAnsi(ptr);
        }

        public void Dispose()
        {
        }

        public void SetKey(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey)
        {
            crypto_box_beforenm( SharedSecretKey,publicKey.ToArray(), secretKey.ToArray());
        }

        public void Encrypt(Span<byte> cipher, Span<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce)
        {
            var complete = new Span<byte>( new byte[mac.Length+cipher.Length]);

            LibSodium.crypto_secretbox_easy(ref cipher.GetPinnableReference(), complete.ToArray(), complete.Length, nonce.ToArray(), SharedSecretKey);

            complete.Slice(0, mac.Length).CopyTo(mac);
            complete.Slice(mac.Length).CopyTo(cipher);
        }

        public void Encrypt(Span<byte> cipher, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce)
        {
            LibSodium.crypto_secretbox_easy(ref cipher.GetPinnableReference(), message.ToArray(), message.Length, nonce.ToArray(), SharedSecretKey);
        }

        public bool TryDecrypt(Span<byte> message, ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce)
        {
            return LibSodium.crypto_secretbox_open_easy(ref message.GetPinnableReference(), cipher.ToArray(), cipher.Length, nonce.ToArray(), SharedSecretKey) == 0;
        }

        public bool TryDecrypt(Span<byte> message, ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce)
        {
            var complete = new Span<byte>(new byte[mac.Length + cipher.Length]);
            mac.CopyTo(complete);

            cipher.CopyTo(complete.Slice(mac.Length));

            return LibSodium.crypto_secretbox_open_easy(ref message.GetPinnableReference(), complete.ToArray(), complete.Length, nonce.ToArray(), SharedSecretKey) == 0;
        }
    }
}
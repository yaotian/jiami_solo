// WhCrypto.cs — 文华指标加密工具 · C# 加密实现
//
// 与 C++ (wh_crypto.h/cpp) 和 Python (wh_pack_ref.py) 保持算法与字节序完全一致。
// 使用 .NET Framework 4.7.2 内置的 System.Security.Cryptography。
//
// 提供：
//   - SHA-256（内置 System.Security.Cryptography.SHA256）
//   - HMAC-SHA256（内置 HMACSHA256）
//   - HKDF-SHA256（手写，RFC 5869）
//   - AES-256-GCM（.NET Core 3.0+ / .NET 5+ 内置；.NET Framework 用 BouncyCastle 或自定义）
//
// ⚠ .NET Framework 4.7.2 没有 AesGcm 类！
//   选项：
//   1. 使用 System.Security.Cryptography.Aes + CTR 手动实现 GCM（GHASH 需手写）
//   2. 使用 BouncyCastle（外部 DLL）
//   3. 使用 Windows CNG (BCrypt) 直接调用
//
//   选择方案 3（Windows CNG）：无需外部 DLL，与 Windows 平台紧密集成。
//   使用 BCryptEncrypt/BCryptDecrypt 的 BCRYPT_CHAIN_MODE_GCM。
using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace WHCryptoManager.Crypto
{
    // ============================================================
    // HKDF-SHA256 (RFC 5869)
    // ============================================================
    public static class HkdfSha256
    {
        public static byte[] DeriveKey(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            if (salt == null || salt.Length == 0)
                salt = new byte[32]; // 默认 salt = 32 字节零

            // PRK = HMAC-SHA256(salt, IKM)
            using (var hmac = new HMACSHA256(salt))
            {
                byte[] prk = hmac.ComputeHash(ikm);

                byte[] okm = new byte[length];
                byte[] t = Array.Empty<byte>();
                int offset = 0;
                byte counter = 1;

                while (offset < length)
                {
                    // T(i) = HMAC(PRK, T(i-1) || info || counter)
                    using (var hmac2 = new HMACSHA256(prk))
                    {
                        using (var ms = new MemoryStream())
                        {
                            ms.Write(t, 0, t.Length);
                            if (info != null && info.Length > 0)
                                ms.Write(info, 0, info.Length);
                            ms.WriteByte(counter);
                            t = hmac2.ComputeHash(ms.ToArray());
                        }
                    }

                    int copyLen = Math.Min(32, length - offset);
                    Buffer.BlockCopy(t, 0, okm, offset, copyLen);
                    offset += copyLen;
                    counter++;
                }

                return okm;
            }
        }
    }

    // ============================================================
    // AES-256-GCM via Windows CNG (BCrypt)
    // ============================================================
    public static class Aes256Gcm
    {
        // CNG P/Invoke
        [DllImport("bcrypt.dll")]
        private static extern int BCryptOpenAlgorithmProvider(
            out IntPtr hAlgorithm,
            string pszAlgId,
            string pszImplementation,
            uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(
            IntPtr hAlgorithm,
            out IntPtr hKey,
            IntPtr pbKeyObject,
            int cbKeyObject,
            byte[] pbSecret,
            int cbSecret,
            uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(
            IntPtr hKey,
            byte[] pbInput,
            int cbInput,
            IntPtr pvIV,
            byte[] pbOutput,
            int cbOutput,
            out int cbResult,
            int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(
            IntPtr hKey,
            byte[] pbInput,
            int cbInput,
            IntPtr pvIV,
            byte[] pbOutput,
            int cbOutput,
            out int cbResult,
            int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptSetProperty(
            IntPtr hObject,
            string pszProperty,
            byte[] pbInput,
            int cbInput,
            int dwFlags);

        private const string BCRYPT_AES_ALGORITHM = "AES";
        private const string BCRYPT_CHAINING_MODE = "ChainingMode";
        private const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";

        /// <summary>
        /// AES-256-GCM 加密。返回 ciphertext + tag（16 字节）。
        /// nonce 12 字节，aad 可为 null。
        /// </summary>
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] aad,
                                      byte[] plaintext, out byte[] tag)
        {
            tag = null;
            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;

            try
            {
                int ret = BCryptOpenAlgorithmProvider(
                    out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
                if (ret != 0) throw new InvalidOperationException($"BCryptOpenAlgorithmProvider: {ret}");

                byte[] mode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM + "\0");
                ret = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, mode, mode.Length, 0);
                if (ret != 0) throw new InvalidOperationException($"BCryptSetProperty: {ret}");

                ret = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0,
                                                key, key.Length, 0);
                if (ret != 0) throw new InvalidOperationException($"BCryptGenerateKey: {ret}");

                byte[] ciphertext = new byte[plaintext.Length];
                tag = new byte[16];
                int cbResult;

                unsafe
                {
                    fixed (byte* pNonce = nonce)
                    fixed (byte* pAad = aad)
                    fixed (byte* pTag = tag)
                    {
                        var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                        authInfo.Init();
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = nonce.Length;
                        if (aad != null)
                        {
                            authInfo.pbAuthData = pAad;
                            authInfo.cbAuthData = aad.Length;
                        }
                        authInfo.pbTag = pTag;
                        authInfo.cbTag = tag.Length;

                        ret = BcryptAuth.BCryptEncrypt2(hKey, plaintext, plaintext.Length,
                            (IntPtr)(&authInfo), null, 0,
                            ciphertext, ciphertext.Length, out cbResult, 0);
                    }
                }

                if (ret != 0) throw new InvalidOperationException($"BCryptEncrypt: {ret}");
                return ciphertext;
            }
            finally
            {
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        /// <summary>
        /// AES-256-GCM 解密。认证失败返回 false。
        /// </summary>
        public static bool Decrypt(byte[] key, byte[] nonce, byte[] aad,
                                   byte[] ciphertext, byte[] tag,
                                   out byte[] plaintext)
        {
            plaintext = null;
            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;

            try
            {
                int ret = BCryptOpenAlgorithmProvider(
                    out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
                if (ret != 0) return false;

                byte[] mode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM + "\0");
                ret = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, mode, mode.Length, 0);
                if (ret != 0) return false;

                ret = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0,
                                                key, key.Length, 0);
                if (ret != 0) return false;

                plaintext = new byte[ciphertext.Length];
                int cbResult;

                unsafe
                {
                    fixed (byte* pNonce = nonce)
                    fixed (byte* pAad = aad)
                    fixed (byte* pTag = tag)
                    {
                        var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                        authInfo.Init();
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = nonce.Length;
                        if (aad != null)
                        {
                            authInfo.pbAuthData = pAad;
                            authInfo.cbAuthData = aad.Length;
                        }
                        authInfo.pbTag = pTag;
                        authInfo.cbTag = tag.Length;

                        ret = BcryptAuth.BCryptDecrypt2(hKey, ciphertext, ciphertext.Length,
                            (IntPtr)(&authInfo), null, 0,
                            plaintext, plaintext.Length, out cbResult, 0);
                    }
                }

                // STATUS_AUTH_TAG_MISMATCH = 0xC000A002
                if (ret == unchecked((int)0xC000A002)) return false;
                if (ret != 0) return false;

                return true;
            }
            finally
            {
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }
    }

    // ============================================================
    // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO 结构体
    // ============================================================
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public byte* pbNonce;
        public int cbNonce;
        public byte* pbAuthData;
        public int cbAuthData;
        public byte* pbTag;
        public int cbTag;
        public byte* pbMacContext;
        public int cbMacContext;
        public long cbAAD;
        public long cbData;
        public long cbMAC;

        public const int BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

        public void Init()
        {
            cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
            dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
            pbNonce = null; cbNonce = 0;
            pbAuthData = null; cbAuthData = 0;
            pbTag = null; cbTag = 0;
            pbMacContext = null; cbMacContext = 0;
            cbAAD = 0; cbData = 0; cbMAC = 0;
        }
    }

    // ============================================================
    // BCryptEncrypt / BCryptDecrypt 带认证信息的重载
    // CNG 在 GCM 模式时第 4 个参数为 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*
    // ============================================================
    public static class BcryptAuth
    {
        [DllImport("bcrypt.dll", EntryPoint = "BCryptEncrypt")]
        public static extern int BCryptEncrypt2(
            IntPtr hKey,
            byte[] pbInput, int cbInput,
            IntPtr pvPaddingInfo,
            byte[] pbIV, int cbIV,
            byte[] pbOutput, int cbOutput,
            out int cbResult, int dwFlags);

        [DllImport("bcrypt.dll", EntryPoint = "BCryptDecrypt")]
        public static extern int BCryptDecrypt2(
            IntPtr hKey,
            byte[] pbInput, int cbInput,
            IntPtr pvPaddingInfo,
            byte[] pbIV, int cbIV,
            byte[] pbOutput, int cbOutput,
            out int cbResult, int dwFlags);
    }
}

using System;
using System.Security.Cryptography;
using System.Text;

namespace WHCryptoManager.Crypto
{
    public static class WhLicense
    {
        private static readonly byte[] LicenseMagic = new byte[] { (byte)'R', (byte)'E', (byte)'G', 0x00 };
        private const byte LicenseVersion = 1;

        private static byte[] MachineHashFromCode(string machineCode)
        {
            string s = machineCode.ToUpperInvariant();
            int pad = (8 - s.Length % 8) % 8;
            s += new string('=', pad);
            return Base32Decode(s);
        }

        private static byte[] Base32Decode(string input)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            int bits = 0;
            int val = 0;
            var outList = new System.Collections.Generic.List<byte>();
            foreach (char c in input)
            {
                if (c == '=') break;
                int idx = alphabet.IndexOf(c);
                if (idx < 0) throw new FormatException("invalid base32 char");
                val = (val << 5) | idx;
                bits += 5;
                if (bits >= 8)
                {
                    outList.Add((byte)((val >> (bits - 8)) & 0xFF));
                    bits -= 8;
                }
            }
            return outList.ToArray();
        }

        private static string Base32Encode(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var sb = new StringBuilder();
            int bits = 0;
            int val = 0;
            foreach (byte b in data)
            {
                val = (val << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    sb.Append(alphabet[(val >> (bits - 5)) & 0x1F]);
                    bits -= 5;
                }
            }
            if (bits > 0)
                sb.Append(alphabet[(val << (5 - bits)) & 0x1F]);
            return sb.ToString();
        }

        private static byte[] ComputeSignature(byte[] masterKey, byte[] machineHash, long expireUnix, byte flags)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                ms.WriteByte(LicenseVersion);
                ms.Write(machineHash, 0, 8);
                ms.Write(BitConverter.GetBytes(expireUnix), 0, 8);
                ms.WriteByte(flags);
                using (var hmac = new HMACSHA256(masterKey))
                {
                    byte[] full = hmac.ComputeHash(ms.ToArray());
                    byte[] sig = new byte[16];
                    Buffer.BlockCopy(full, 0, sig, 0, 16);
                    return sig;
                }
            }
        }

        public static string GenerateLicenseKey(byte[] masterKey, string machineCode, long expireUnix, byte flags = 0)
        {
            byte[] machineHash = MachineHashFromCode(machineCode);
            byte[] signature = ComputeSignature(masterKey, machineHash, expireUnix, flags);

            var buf = new byte[38];
            Buffer.BlockCopy(LicenseMagic, 0, buf, 0, 4);
            buf[4] = LicenseVersion;
            Buffer.BlockCopy(machineHash, 0, buf, 5, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(expireUnix), 0, buf, 13, 8);
            buf[21] = flags;
            Buffer.BlockCopy(signature, 0, buf, 22, 16);

            return Convert.ToBase64String(buf)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        public static bool VerifyLicenseKey(byte[] masterKey, string licenseKey, string machineCode, long nowUtc)
        {
            try
            {
                string s = licenseKey.Replace("-", "+").Replace("_", "/");
                int pad = (4 - s.Length % 4) % 4;
                s += new string('=', pad);
                byte[] raw = Convert.FromBase64String(s);
                if (raw.Length != 38) return false;
                for (int i = 0; i < 4; i++) if (raw[i] != LicenseMagic[i]) return false;
                if (raw[4] != LicenseVersion) return false;

                byte[] licMachineHash = new byte[8];
                Buffer.BlockCopy(raw, 5, licMachineHash, 0, 8);
                long expireUnix = BitConverter.ToInt64(raw, 13);
                byte flags = raw[21];
                byte[] signature = new byte[16];
                Buffer.BlockCopy(raw, 22, signature, 0, 16);

                byte[] currentHash = MachineHashFromCode(machineCode);
                byte[] expected = ComputeSignature(masterKey, currentHash, expireUnix, flags);
                for (int i = 0; i < 16; i++) if (signature[i] != expected[i]) return false;
                for (int i = 0; i < 8; i++) if (licMachineHash[i] != currentHash[i]) return false;
                if (expireUnix > 0 && nowUtc > expireUnix) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string GenerateMachineCode()
        {
            // 管理端不直接读取客户机器硬件；这里提供一个基于当前机器信息的辅助方法。
            string cpu = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "";
            string info = "CPU:" + cpu;
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(info));
                byte[] truncated = new byte[16];
                Buffer.BlockCopy(hash, 0, truncated, 0, 16);
                return Base32Encode(truncated);
            }
        }
    }
}

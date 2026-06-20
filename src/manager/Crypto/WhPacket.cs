using System;
using System.IO;
using System.Text;

namespace WHCryptoManager.Crypto
{
    public enum ProductId : uint
    {
        T8_WH8 = 1,
        WH6 = 2,
        WH7 = 3,
    }

    public class PackageHeader
    {
        public ProductId ProductId { get; set; }
        public long ExpireUnix { get; set; }
        public string User { get; set; }
        public string Contact { get; set; }
        public string IndicatorVersion { get; set; }
        public string SoftwareName { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
        public byte[] Ciphertext { get; set; }
    }

    public class PayloadPlain
    {
        public string Source { get; set; }
        public string Note { get; set; }
        public byte[] XtrdRaw { get; set; }
    }

    public static class Packet
    {
        private const byte PayloadDeliverySource = 0;
        private const byte PayloadDeliveryXtrdRaw = 1;
        private static readonly byte[] MAGIC = { (byte)'W', (byte)'H', (byte)'P', (byte)'K', (byte)'G', 0, 1, 0 };
        private const uint VERSION = 2;
        private static readonly byte[] SALT_PAYLOAD = Encoding.ASCII.GetBytes("WH-PAYLOAD");

        private static byte[] SerializePayload(PayloadPlain p)
        {
            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
                byte[] src = Encoding.UTF8.GetBytes(p.Source ?? "");
                byte[] note = Encoding.UTF8.GetBytes(p.Note ?? "");
                w.Write((uint)src.Length);
                w.Write(src);
                w.Write((ushort)note.Length);
                w.Write(note);
                byte mode = (p.XtrdRaw != null && p.XtrdRaw.Length > 0)
                    ? PayloadDeliveryXtrdRaw : PayloadDeliverySource;
                w.Write(mode);
                if (mode == PayloadDeliveryXtrdRaw)
                {
                    w.Write((uint)p.XtrdRaw.Length);
                    w.Write(p.XtrdRaw);
                }
                return ms.ToArray();
            }
        }

        private static PayloadPlain DeserializePayload(byte[] data)
        {
            using (var ms = new MemoryStream(data))
            using (var r = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true))
            {
                uint srcLen = r.ReadUInt32();
                string source = Encoding.UTF8.GetString(r.ReadBytes((int)srcLen));
                ushort noteLen = r.ReadUInt16();
                string note = Encoding.UTF8.GetString(r.ReadBytes(noteLen));
                byte[] xtrdRaw = null;
                if (ms.Position < ms.Length)
                {
                    byte mode = r.ReadByte();
                    if (mode == PayloadDeliveryXtrdRaw)
                    {
                        uint xlen = r.ReadUInt32();
                        xtrdRaw = r.ReadBytes((int)xlen);
                    }
                }
                return new PayloadPlain { Source = source, Note = note, XtrdRaw = xtrdRaw };
            }
        }

        public static byte[] Build(byte[] masterKey, PackageHeader hdr, PayloadPlain payload)
        {
            if (masterKey.Length != 32) throw new ArgumentException("master key must be 32 bytes");
            if (hdr.Nonce == null || hdr.Nonce.Length != 12) throw new ArgumentException("nonce must be 12 bytes");

            byte[] userBytes = Encoding.UTF8.GetBytes(hdr.User ?? "");
            byte[] derived = HkdfSha256.DeriveKey(masterKey, SALT_PAYLOAD, userBytes, 32);

            using (var aadMs = new MemoryStream())
            using (var aadW = new BinaryWriter(aadMs))
            {
                aadW.Write((uint)hdr.ProductId);
                aadW.Write(hdr.ExpireUnix);
                aadW.Write((ushort)userBytes.Length);
                aadW.Write(userBytes);
                byte[] aad = aadMs.ToArray();

                byte[] pt = SerializePayload(payload);
                byte[] tag;
                byte[] ct = Aes256Gcm.Encrypt(derived, hdr.Nonce, aad, pt, out tag);
                hdr.Tag = tag;
                hdr.Ciphertext = ct;
            }

            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write(MAGIC);
                w.Write(VERSION);
                long hdrStart = ms.Position;
                w.Write(0u);

                w.Write((uint)hdr.ProductId);
                w.Write(hdr.ExpireUnix);

                byte[] ub = Encoding.UTF8.GetBytes(hdr.User ?? "");
                w.Write((ushort)ub.Length);
                w.Write(ub);

                byte[] cb = Encoding.UTF8.GetBytes(hdr.Contact ?? "");
                w.Write((ushort)cb.Length);
                w.Write(cb);

                byte[] iv = Encoding.UTF8.GetBytes(hdr.IndicatorVersion ?? "1.0.0");
                w.Write((ushort)iv.Length);
                w.Write(iv);

                byte[] sn = Encoding.UTF8.GetBytes(hdr.SoftwareName ?? "WH8Crypto");
                w.Write((ushort)sn.Length);
                w.Write(sn);

                w.Write((byte)12);
                w.Write(hdr.Nonce);
                w.Write(hdr.Tag);
                w.Write((uint)hdr.Ciphertext.Length);
                w.Write(hdr.Ciphertext);

                long hdrEnd = ms.Position;
                long hdrLen = hdrEnd - hdrStart - 4;
                ms.Position = hdrStart;
                w.Write((uint)hdrLen);
                ms.Position = hdrEnd;
                return ms.ToArray();
            }
        }

        public static bool Parse(byte[] blob, byte[] masterKey,
            out PackageHeader hdr, out PayloadPlain payload, out string error)
        {
            hdr = null;
            payload = null;
            error = null;
            try
            {
                using (var ms = new MemoryStream(blob))
                using (var r = new BinaryReader(ms))
                {
                    byte[] magic = r.ReadBytes(8);
                    if (!CompareBytes(magic, MAGIC)) { error = "bad magic"; return false; }
                    if (r.ReadUInt32() != VERSION) { error = "unsupported version"; return false; }
                    r.ReadUInt32(); // header_len

                    hdr = new PackageHeader();
                    hdr.ProductId = (ProductId)r.ReadUInt32();
                    hdr.ExpireUnix = r.ReadInt64();
                    hdr.User = Encoding.UTF8.GetString(r.ReadBytes(r.ReadUInt16()));
                    hdr.Contact = Encoding.UTF8.GetString(r.ReadBytes(r.ReadUInt16()));
                    hdr.IndicatorVersion = Encoding.UTF8.GetString(r.ReadBytes(r.ReadUInt16()));
                    hdr.SoftwareName = Encoding.UTF8.GetString(r.ReadBytes(r.ReadUInt16()));
                    if (r.ReadByte() != 12) { error = "bad nonce len"; return false; }
                    hdr.Nonce = r.ReadBytes(12);
                    hdr.Tag = r.ReadBytes(16);
                    hdr.Ciphertext = r.ReadBytes((int)r.ReadUInt32());

                    byte[] userBytes = Encoding.UTF8.GetBytes(hdr.User);
                    byte[] derived = HkdfSha256.DeriveKey(masterKey, SALT_PAYLOAD, userBytes, 32);
                    using (var aadMs = new MemoryStream())
                    using (var aadW = new BinaryWriter(aadMs))
                    {
                        aadW.Write((uint)hdr.ProductId);
                        aadW.Write(hdr.ExpireUnix);
                        aadW.Write((ushort)userBytes.Length);
                        aadW.Write(userBytes);
                        byte[] aad = aadMs.ToArray();
                        byte[] pt;
                        if (!Aes256Gcm.Decrypt(derived, hdr.Nonce, aad, hdr.Ciphertext, hdr.Tag, out pt))
                        {
                            error = "authentication failed";
                            return false;
                        }
                        payload = DeserializePayload(pt);
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}

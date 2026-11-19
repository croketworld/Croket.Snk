using System.Security.Cryptography;

namespace Croket.Snk;

/// <summary>Un .snk es un PRIVATEKEYBLOB de CryptoAPI en crudo (o un blob público si se hizo con sn -p).</summary>
public sealed class StrongNameKey
{
    const uint CALG_RSA_SIGN = 0x00002400;
    const uint CALG_SHA1 = 0x00008004;
    const uint MAGIC_RSA2 = 0x32415352; // clave privada
    const uint MAGIC_RSA1 = 0x31415352; // clave pública

    public byte[] PrivateBlob { get; }      // contenido literal del .snk
    public byte[] PublicKeyBlob { get; }    // lo que va en la columna PublicKey del AssemblyDef
    public byte[] PublicKeyToken { get; }
    public int BitLength { get; }
    public bool HasPrivate => PrivateBlob.Length > 0;

    StrongNameKey(byte[] priv, byte[] pub, int bits)
    { PrivateBlob = priv; PublicKeyBlob = pub; BitLength = bits; PublicKeyToken = TokenOf(pub); }

    public static byte[] TokenOf(byte[] publicKeyBlob)
    {
        var h = SHA1.HashData(publicKeyBlob);
        var t = new byte[8];
        for (int i = 0; i < 8; i++) t[i] = h[h.Length - 1 - i];
        return t;
    }

    public static StrongNameKey Create(int bits = 2048)
    {
        using var rsa = RSA.Create(bits);          // CNG o OpenSSL: multiplataforma
        var p = rsa.ExportParameters(true);
        return new StrongNameKey(BuildPrivateBlob(p), BuildPublicKeyBlob(p.Modulus!, p.Exponent!), bits);
    }

    public static StrongNameKey Load(string file) => Parse(File.ReadAllBytes(file));

    public static StrongNameKey Parse(byte[] b)
    {
        if (b.Length >= 20 && b[0] == 0x07)                       // PRIVATEKEYBLOB
        {
            var p = ReadPrivateBlob(b);
            return new StrongNameKey(b, BuildPublicKeyBlob(p.Modulus!, p.Exponent!), p.Modulus!.Length * 8);
        }
        if (b.Length > 32 && BitConverter.ToUInt32(b, 0) == CALG_RSA_SIGN) // blob público (sn -p)
        {
            int cb = BitConverter.ToInt32(b, 8);
            if (cb + 12 != b.Length) throw new InvalidDataException("Blob público corrupto.");
            return new StrongNameKey([], b, BitConverter.ToInt32(b, 24));
        }
        throw new InvalidDataException("No es un .snk válido (se esperaba PRIVATEKEYBLOB o blob público de strong name).");
    }

    public bool MatchesCspPublic(byte[] cspPublicBlob) =>
        PublicKeyBlob.AsSpan(12).SequenceEqual(cspPublicBlob);   // sin la cabecera de strong name

    static RSAParameters ReadPrivateBlob(byte[] b)
    {
        if (BitConverter.ToUInt32(b, 8) != MAGIC_RSA2) throw new InvalidDataException("Magic RSA2 ausente.");
        int cb = BitConverter.ToInt32(b, 12) / 8, half = cb / 2, o = 20;
        byte[] Take(int n)
        {
            var s = new byte[n];
            Buffer.BlockCopy(b, o, s, 0, n);
            o += n; Array.Reverse(s);              // CSP = little endian, RSAParameters = big endian
            return s;
        }
        return new RSAParameters
        {
            Modulus = Take(cb),
            P = Take(half),
            Q = Take(half),
            DP = Take(half),
            DQ = Take(half),
            InverseQ = Take(half),
            D = Take(cb),
            Exponent = ToBigEndian(BitConverter.ToUInt32(b, 16))
        };
    }

    static byte[] BuildPrivateBlob(RSAParameters p)
    {
        int cb = p.Modulus!.Length, half = cb / 2;
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms))
        {
            w.Write((byte)0x07); w.Write((byte)0x02); w.Write((ushort)0); w.Write(CALG_RSA_SIGN);
            w.Write(MAGIC_RSA2); w.Write((uint)(cb * 8)); w.Write(ToUInt32(p.Exponent!));
            void Put(byte[]? v, int n)
            {
                var src = v ?? [];
                if (src.Length > n) throw new InvalidDataException("Parámetro RSA de tamaño inesperado.");
                var buf = new byte[n];
                Array.Copy(src, 0, buf, n - src.Length, src.Length);
                Array.Reverse(buf); w.Write(buf);
            }
            Put(p.Modulus, cb); Put(p.P, half); Put(p.Q, half);
            Put(p.DP, half); Put(p.DQ, half); Put(p.InverseQ, half); Put(p.D, cb);
        }
        return ms.ToArray();
    }

    static byte[] BuildPublicKeyBlob(byte[] modulus, byte[] exponent)
    {
        using var inner = new MemoryStream();
        using (var w = new BinaryWriter(inner))
        {
            w.Write((byte)0x06); w.Write((byte)0x02); w.Write((ushort)0); w.Write(CALG_RSA_SIGN);
            w.Write(MAGIC_RSA1); w.Write((uint)(modulus.Length * 8)); w.Write(ToUInt32(exponent));
            var m = (byte[])modulus.Clone(); Array.Reverse(m); w.Write(m);
        }
        var ib = inner.ToArray();
        using var outer = new MemoryStream();
        using (var w = new BinaryWriter(outer))
        { w.Write(CALG_RSA_SIGN); w.Write(CALG_SHA1); w.Write((uint)ib.Length); w.Write(ib); }
        return outer.ToArray();
    }

    static uint ToUInt32(byte[] bigEndian)
    {
        uint v = 0;
        foreach (var b in bigEndian) v = (v << 8) | b;
        return v;
    }

    static byte[] ToBigEndian(uint v)
    {
        var l = new List<byte>(4);
        for (int i = 3; i >= 0; i--)
        {
            byte b = (byte)(v >> (i * 8));
            if (l.Count > 0 || b != 0) l.Add(b);
        }
        return l.Count == 0 ? [0] : [.. l];
    }
}
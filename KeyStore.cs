using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Croket.Snk;

public sealed record StoreResult(bool Existed, bool Installed, string Location, string Note);

public static class KeyStore
{
    public static StoreResult Ensure(string container, StrongNameKey key, KeyScope scope, bool force, bool dry)
        => OperatingSystem.IsWindows() ? Win.Ensure(container, key, scope, force, dry)
                                       : Nix.Ensure(container, key, scope, force, dry);

    public static StrongNameKey? TryExport(string container, KeyScope scope)
        => OperatingSystem.IsWindows() ? Win.TryExport(container, scope) : Nix.TryExport(container, scope);

    [SupportedOSPlatform("windows")]
    static class Win
    {
        const string Provider = "Microsoft Strong Cryptographic Provider"; // PROV_RSA_FULL, proveedor clásico de sn.exe

        static CspParameters Csp(string c, KeyScope s, bool existing) => new(1, Provider, c)
        {
            KeyNumber = (int)System.Security.Cryptography.KeyNumber.Signature,   // AT_SIGNATURE
            Flags = (s == KeyScope.Machine ? CspProviderFlags.UseMachineKeyStore : CspProviderFlags.NoFlags)
                  | (existing ? CspProviderFlags.UseExistingKey : CspProviderFlags.NoFlags)
        };

        static byte[]? Read(string c, KeyScope s)
        {
            try { using var rsa = new RSACryptoServiceProvider(Csp(c, s, true)); return rsa.ExportCspBlob(false); }
            catch (CryptographicException) { return null; }
        }

        public static StrongNameKey? TryExport(string c, KeyScope s)
        {
            try
            {
                using var rsa = new RSACryptoServiceProvider(Csp(c, s, true));
                return StrongNameKey.Parse(rsa.ExportCspBlob(true));
            }
            catch (CryptographicException) { return null; }
        }

        public static StoreResult Ensure(string c, StrongNameKey key, KeyScope s, bool force, bool dry)
        {
            if (!key.HasPrivate) throw new InvalidOperationException("El .snk no contiene clave privada; no se puede registrar.");
            var current = Read(c, s);
            string loc = $"{(s == KeyScope.Machine ? "%ProgramData%\\Microsoft\\Crypto\\RSA\\MachineKeys" : "%APPDATA%\\Microsoft\\Crypto\\RSA")} :: {c}";
            if (current is not null && key.MatchesCspPublic(current) && !force)
                return new(true, false, loc, "Ya registrado con esta misma clave.");
            if (dry) return new(current is not null, false, loc, "dry-run: no se escribe.");

            using (var rsa = new RSACryptoServiceProvider(Csp(c, s, false)))
            {
                rsa.ImportCspBlob(key.PrivateBlob);
                rsa.PersistKeyInCsp = true;
            }
            return new(current is not null, true, loc, current is null ? "Contenedor creado." : "Contenedor sobrescrito.");
        }
    }

    static class Nix
    {
        static string Dir(KeyScope s) => s == KeyScope.Machine
            ? "/etc/croket-snk/keys"
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "croket-snk", "keys");

        static string FileFor(string c, KeyScope s)
        {
            foreach (var ch in Path.GetInvalidFileNameChars()) c = c.Replace(ch, '_');
            return Path.Combine(Dir(s), c + ".snk");
        }

        public static StrongNameKey? TryExport(string c, KeyScope s)
            => File.Exists(FileFor(c, s)) ? StrongNameKey.Load(FileFor(c, s)) : null;

        public static StoreResult Ensure(string c, StrongNameKey key, KeyScope s, bool force, bool dry)
        {
            string f = FileFor(c, s);
            bool exists = File.Exists(f);
            if (exists && !force && StrongNameKey.Load(f).PublicKeyBlob.SequenceEqual(key.PublicKeyBlob))
                return new(true, false, f, "Ya registrado con esta misma clave.");
            if (dry) return new(exists, false, f, "dry-run: no se escribe.");
            try { Directory.CreateDirectory(Dir(s)); }
            catch (UnauthorizedAccessException) when (s == KeyScope.Machine)
            { throw new UnauthorizedAccessException($"Sin permisos sobre {Dir(s)}: ejecuta con sudo o usa --scope user."); }
            File.WriteAllBytes(f, key.PrivateBlob);
            File.SetUnixFileMode(f, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return new(exists, true, f, "Unix no tiene CSP. Equivalente Mono: sn -i \"" + f + "\" " + c);
        }
    }
}
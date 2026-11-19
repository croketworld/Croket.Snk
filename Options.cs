namespace Croket.Snk;

public enum KeyScope { Machine, User }

public sealed class Options
{
    public List<string> Targets { get; } = [];
    public string? Container, KeyPath;
    public int Bits = 2048;
    public KeyScope Scope = KeyScope.Machine;
    public bool Sign, ForceKey, ForceRegister, ForceRekey, PublicOnly, DryRun, Json;
    public bool Backup = true;

    public static Options Parse(string[] a)
    {
        var o = new Options();
        for (int i = 0; i < a.Length; i++)
        {
            string s = a[i];
            string Next() => i + 1 < a.Length ? a[++i] : throw new ArgumentException($"falta el valor de {s}");
            switch (s)
            {
                case "--container": o.Container = Next(); break;
                case "--key": o.KeyPath = Next(); break;
                case "--bits": o.Bits = int.Parse(Next()); break;
                case "--scope":
                    o.Scope = Next().ToLowerInvariant() switch
                    {
                        "machine" => KeyScope.Machine,
                        "user" => KeyScope.User,
                        _ => throw new ArgumentException("--scope admite machine|user")
                    };
                    break;
                case "--sign": o.Sign = true; break;
                case "--force-key": o.ForceKey = true; break;
                case "--force-register": o.ForceRegister = true; break;
                case "--force-rekey": o.ForceRekey = true; break;
                case "--public-key-only": o.PublicOnly = true; break;
                case "--no-backup": o.Backup = false; break;
                case "--dry-run": o.DryRun = true; break;
                case "--json": o.Json = true; break;
                default:
                    if (s.StartsWith('-')) throw new ArgumentException("opción desconocida: " + s);
                    o.Targets.Add(s); break;
            }
        }
        if (o.Targets.Count == 0) throw new ArgumentException("falta la ruta del ensamblado");
        if (o.Bits is not (1024 or 2048 or 4096)) throw new ArgumentException("--bits: 1024, 2048 o 4096");
        return o;
    }
}
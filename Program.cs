using System.Text.Json;

namespace Croket.Snk;

public sealed record RunReport
{
    public required string Assembly { get; init; }
    public required string SimpleName { get; init; }
    public string? Version { get; init; }
    public string? TargetFramework { get; init; }
    public string? PreviousToken { get; init; }
    public bool WasSigned { get; init; }
    public bool WasDelaySigned { get; init; }
    public required string SnkPath { get; init; }
    public required string Container { get; init; }
    public required string Scope { get; init; }
    public bool SnkCreated { get; init; }
    public bool Registered { get; init; }
    public string? StoreLocation { get; init; }
    public string? StoreNote { get; init; }
    public bool Signed { get; init; }
    public string? NewToken { get; init; }
    public IReadOnlyDictionary<string, string?>? Attributes { get; init; }
    public string? Warning { get; init; }
}

internal static class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "-?") { Help(); return args.Length == 0 ? 2 : 0; }

        Options o;
        try { o = Options.Parse(args); }
        catch (Exception e) { Console.Error.WriteLine("Argumentos: " + e.Message); Help(); return 2; }

        var reports = new List<RunReport>();
        int rc = 0;
        foreach (var t in o.Targets)
        {
            try
            {
                var r = Process(Path.GetFullPath(t), o);
                reports.Add(r);
                if (!o.Json) Print(r);
            }
            catch (Exception e) { Console.Error.WriteLine($"[ERROR] {t}: {e.Message}"); rc = 1; }
        }
        if (o.Json) Console.WriteLine(JsonSerializer.Serialize(reports, new JsonSerializerOptions { WriteIndented = true }));
        return rc;
    }

    static RunReport Process(string path, Options o)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("No existe el ensamblado.", path);
        var info = AssemblyProbe.Probe(path);                       // 1) reflexión
        if (!info.IsManaged) throw new InvalidDataException("PE nativo: no es un ensamblado administrado.");

        string dir = Path.GetDirectoryName(path)!;
        string stem = Path.GetFileNameWithoutExtension(path);
        string snk = o.KeyPath is null ? Path.Combine(dir, stem + ".snk") : Path.GetFullPath(o.KeyPath);
        string container = o.Container ?? info.KeyContainer ?? info.SimpleName;

        // 2) clave: existente en disco > existente en el almacén global > nueva
        StrongNameKey key; bool created = false;
        if (File.Exists(snk) && !o.ForceKey) key = StrongNameKey.Load(snk);
        else
        {
            key = (!o.ForceKey ? KeyStore.TryExport(container, o.Scope) : null) ?? StrongNameKey.Create(o.Bits);
            if (!o.DryRun) File.WriteAllBytes(snk, key.PrivateBlob);
            created = true;
        }
        if (!key.HasPrivate) throw new InvalidOperationException($"{snk} es solo clave pública; no permite firmar ni registrar.");

        string? warn = info.HasPublicKey && !info.PublicKey.SequenceEqual(key.PublicKeyBlob)
            ? "El ensamblado ya lleva otra clave pública: firmar CAMBIA su identidad y rompe las referencias existentes."
            : null;
        if (o.Sign && warn is not null && !o.ForceRekey) throw new InvalidOperationException(warn + " Confirma con --force-rekey.");

        if (o.PublicOnly && !o.DryRun)
            File.WriteAllBytes(Path.Combine(dir, stem + ".public.snk"), key.PublicKeyBlob);

        // 3) registro global idempotente
        var store = KeyStore.Ensure(container, key, o.Scope, o.ForceRegister, o.DryRun);

        // 4) firma real (opcional)
        bool signed = false; string? newToken = null;
        if (o.Sign)
        {
            CecilSigner.Sign(path, key, o.Backup, o.DryRun, info);
            signed = !o.DryRun;
            newToken = o.DryRun ? Convert.ToHexStringLower(key.PublicKeyToken)
                                : AssemblyProbe.Probe(path).PublicKeyToken;
        }

        return new RunReport
        {
            Assembly = path,
            SimpleName = info.SimpleName,
            Version = info.Version?.ToString(),
            TargetFramework = info.TargetFramework,
            PreviousToken = info.PublicKeyToken,
            WasSigned = info.StrongNameSigned,
            WasDelaySigned = info.DelayOrPublicSigned,
            SnkPath = snk,
            Container = container,
            Scope = o.Scope.ToString().ToLowerInvariant(),
            SnkCreated = created,
            Registered = store.Installed,
            StoreLocation = store.Location,
            StoreNote = store.Note,
            Signed = signed,
            NewToken = newToken ?? Convert.ToHexStringLower(key.PublicKeyToken),
            Attributes = info.Attributes,
            Warning = warn
        };
    }

    static void Print(RunReport r)
    {
        Console.WriteLine($"── {r.SimpleName} v{r.Version}  [{r.TargetFramework}]");
        Console.WriteLine($"   estado previo : {(r.WasSigned ? "firmado" : r.WasDelaySigned ? "delay/public signed" : "sin firma")}  token={r.PreviousToken ?? "—"}");
        foreach (var a in r.Attributes ?? new Dictionary<string, string?>())
            Console.WriteLine($"   attr          : {a.Key} = {a.Value}");
        Console.WriteLine($"   snk           : {r.SnkPath} ({(r.SnkCreated ? "creado" : "reutilizado")})");
        Console.WriteLine($"   contenedor    : {r.Container} [{r.Scope}] → {(r.Registered ? "registrado" : "sin cambios")}");
        Console.WriteLine($"   almacén       : {r.StoreLocation}  {r.StoreNote}");
        Console.WriteLine($"   firma         : {(r.Signed ? "APLICADA" : "no aplicada")}  token={r.NewToken}");
        if (r.Warning is not null) Console.WriteLine($"   ⚠ {r.Warning}");
    }

    static void Help() => Console.WriteLine("""
        croket-snk <ensamblado.dll|exe> [más ensamblados] [opciones]

          --sign                 Reescribe y firma el ensamblado (Mono.Cecil)
          --key <ruta.snk>       Usar/crear el .snk en esa ruta (def: junto al ensamblado, mismo nombre)
          --container <nombre>   Contenedor global (def: AssemblyKeyNameAttribute o nombre simple)
          --scope machine|user   Ámbito del registro (def: machine; requiere admin/root)
          --bits 1024|2048|4096  Tamaño si hay que generar clave (def: 2048)
          --force-key            Regenerar el .snk aunque exista
          --force-register       Sobrescribir el contenedor aunque exista
          --force-rekey          Aceptar el cambio de identidad de un ensamblado ya firmado
          --public-key-only      Exportar además <nombre>.public.snk
          --no-backup            No crear .bak al reescribir
          --dry-run              Solo informar
          --json                 Salida JSON
        """);
}
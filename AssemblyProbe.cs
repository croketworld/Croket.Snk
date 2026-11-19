using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace Croket.Snk;

public sealed class AssemblyReport
{
    public required string Path { get; init; }
    public required string SimpleName { get; init; }
    public Version? Version { get; init; }
    public bool IsManaged { get; init; }
    public bool HasPublicKey { get; init; }
    public bool StrongNameSigned { get; init; }
    public bool DelayOrPublicSigned => HasPublicKey && !StrongNameSigned;
    public byte[] PublicKey { get; init; } = [];
    public string? PublicKeyToken { get; init; }
    public bool HasEmbeddedPdb { get; init; }
    public string? ExternalPdbPath { get; init; }
    public Dictionary<string, string?> Attributes { get; } = new(StringComparer.Ordinal);
    public string? KeyContainer => Attributes.GetValueOrDefault("AssemblyKeyNameAttribute");
    public string? KeyFile => Attributes.GetValueOrDefault("AssemblyKeyFileAttribute");
    public string? TargetFramework => Attributes.GetValueOrDefault("TargetFrameworkAttribute");
}

public static class AssemblyProbe
{
    public static AssemblyReport Probe(string path)
    {
        using var fs = File.OpenRead(path);
        using var pe = new PEReader(fs);
        if (!pe.HasMetadata || pe.PEHeaders.CorHeader is null)
            return new AssemblyReport { Path = path, SimpleName = System.IO.Path.GetFileNameWithoutExtension(path), IsManaged = false };

        var md = pe.GetMetadataReader();
        var def = md.GetAssemblyDefinition();
        var pk = md.GetBlobBytes(def.PublicKey);
        var cor = pe.PEHeaders.CorHeader;

        string? extPdb = null; bool embedded = false;
        foreach (var e in pe.ReadDebugDirectory())
        {
            if (e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb) embedded = true;
            if (e.Type == DebugDirectoryEntryType.CodeView)
                extPdb = pe.ReadCodeViewDebugDirectoryData(e).Path;
        }

        var r = new AssemblyReport
        {
            Path = path,
            SimpleName = md.GetString(def.Name),
            Version = def.Version,
            IsManaged = true,
            HasPublicKey = pk.Length > 0,
            PublicKey = pk,
            PublicKeyToken = pk.Length > 0 ? Convert.ToHexStringLower(StrongNameKey.TokenOf(pk)) : null,
            StrongNameSigned = cor.Flags.HasFlag(CorFlags.StrongNameSigned),
            HasEmbeddedPdb = embedded,
            ExternalPdbPath = extPdb
        };

        ReadAttributesViaReflection(path, md, def, r);
        return r;
    }

    static void ReadAttributesViaReflection(string path, MetadataReader md, AssemblyDefinition def, AssemblyReport r)
    {
        // Ensamblado "core" correcto para MetadataLoadContext según el target del objetivo.
        bool netcore = md.AssemblyReferences
            .Select(h => md.GetString(md.GetAssemblyReference(h).Name))
            .Any(n => n == "System.Runtime");
        string core = netcore ? "System.Runtime" : "mscorlib";

        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Directory.GetFiles(RuntimeEnvironment.GetRuntimeDirectory(), "*.dll"))
            files[System.IO.Path.GetFileNameWithoutExtension(f)] = f;
        foreach (var f in Directory.GetFiles(System.IO.Path.GetDirectoryName(path)!, "*.dll"))
            files[System.IO.Path.GetFileNameWithoutExtension(f)] = f;   // las dependencias locales ganan
        files[System.IO.Path.GetFileNameWithoutExtension(path)] = path;

        try
        {
            using var mlc = new MetadataLoadContext(new PathAssemblyResolver(files.Values), core);
            var asm = mlc.LoadFromAssemblyPath(path);          // sin ejecutar código, sin bloquear al salir del using
            foreach (var a in asm.GetCustomAttributesData())
            {
                string name = a.AttributeType.Name;
                var parts = new List<string>();
                foreach (var ca in a.ConstructorArguments) parts.Add(Fmt(ca.Value));
                foreach (var na in a.NamedArguments) parts.Add($"{na.MemberName}={Fmt(na.TypedValue.Value)}");
                r.Attributes[name] = string.Join(", ", parts);
            }
            return;
        }
        catch (Exception ex) when (ex is FileNotFoundException or FileLoadException or InvalidOperationException)
        {
            Console.Error.WriteLine($"[aviso] MLC incompleto ({ex.GetType().Name}); listado de atributos vía MetadataReader (solo nombres).");
        }

        foreach (var h in def.GetCustomAttributes())
            r.Attributes[AttrTypeName(md, md.GetCustomAttribute(h))] ??= "<no decodificado>";
    }

    static string Fmt(object? v) => v switch
    {
        null => "null",
        string s => $"\"{s}\"",
        Type t => t.FullName ?? t.Name,
        Array a => "[" + string.Join(",", a.Cast<object?>().Select(Fmt)) + "]",
        _ => v.ToString() ?? ""
    };

    static string AttrTypeName(MetadataReader md, CustomAttribute a) => a.Constructor.Kind switch
    {
        HandleKind.MemberReference => ParentName(md, md.GetMemberReference((MemberReferenceHandle)a.Constructor).Parent),
        HandleKind.MethodDefinition => TypeDefName(md, md.GetMethodDefinition((MethodDefinitionHandle)a.Constructor).GetDeclaringType()),
        _ => "<desconocido>"
    };

    static string ParentName(MetadataReader md, EntityHandle h) => h.Kind switch
    {
        HandleKind.TypeReference => Full(md, md.GetTypeReference((TypeReferenceHandle)h)),
        HandleKind.TypeDefinition => TypeDefName(md, (TypeDefinitionHandle)h),
        _ => "<tipo especificado>"
    };

    static string Join(TypeReference tr, MetadataReader md) => ""; // no usado

static string Full(MetadataReader md, TypeReference tr)
    {
        string ns = md.GetString(tr.Namespace), n = md.GetString(tr.Name);
        return ns.Length == 0 ? n : ns + "." + n;
    }
    static string TypeDefName(MetadataReader md, TypeDefinitionHandle h)
    {
        var td = md.GetTypeDefinition(h);
        string ns = md.GetString(td.Namespace), n = md.GetString(td.Name);
        return ns.Length == 0 ? n : ns + "." + n;
    }
}
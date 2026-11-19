using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Croket.Snk;

public static class CecilSigner
{
    public static void Sign(string path, StrongNameKey key, bool backup, bool dry, AssemblyReport info)
    {
        if (!key.HasPrivate) throw new InvalidOperationException("Se necesita la clave privada para firmar.");
        if (dry) return;

        string tmp = path + ".signed.tmp";
        string? pdb = info.ExternalPdbPath is { Length: > 0 } p && File.Exists(p) ? p : null;
        bool symbols = info.HasEmbeddedPdb || pdb is not null;

        void Write(bool withSymbols)
        {
            var rp = new ReaderParameters { InMemory = true, ReadSymbols = withSymbols };
            if (withSymbols)
                rp.SymbolReaderProvider = info.HasEmbeddedPdb ? new EmbeddedPortablePdbReaderProvider() : new PortablePdbReaderProvider();

            using var asm = AssemblyDefinition.ReadAssembly(path, rp);

            // Una firma mejorada heredada (enhanced strong name) invalidaría la nueva.
            foreach (var a in asm.CustomAttributes
                .Where(a => a.AttributeType.FullName == "System.Reflection.AssemblySignatureKeyAttribute").ToArray())
                asm.CustomAttributes.Remove(a);

            asm.Name.PublicKey = key.PublicKeyBlob;
            asm.Name.HasPublicKey = true;

            var wp = new WriterParameters { StrongNameKeyBlob = key.PrivateBlob, WriteSymbols = withSymbols };
            if (withSymbols)
                wp.SymbolWriterProvider = info.HasEmbeddedPdb ? new EmbeddedPortablePdbWriterProvider() : new PortablePdbWriterProvider();

            asm.Write(tmp, wp);
        }

        try { Write(symbols); }
        catch (Exception e) when (symbols && e is BadImageFormatException or InvalidOperationException)
        {
            Console.Error.WriteLine($"[aviso] Símbolos no portables ({e.Message}); firmando sin PDB.");
            Write(false);
        }

        if (backup) File.Copy(path, path + ".bak", true);
        File.Move(tmp, path, overwrite: true);
    }
}
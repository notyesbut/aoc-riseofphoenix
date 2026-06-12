// DecompAoCTargets - targeted AoC client decompile exporter for protocol RE.
// Usage with analyzeHeadless:
//   -postScript DecompAoCTargets.java <output-dir> [hex-va ...]
// @category AOC
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompAoCTargets extends GhidraScript {
    private static final String DEFAULT_OUT = "ghidra-out/aoc-targets";
    private static final String[] DEFAULT_TARGETS = {
        "143f329d0", // UActorChannel receive/process bunch area
        "143f2c340", // older ReadContentBlockHeader candidate
        "143f2da40", // older ReadContentBlockPayload candidate
        "143f2dc60", // older ReadPropertyChangeHeader candidate
        "143f2f820", // older FObjectReplicator::ReceivedBunch candidate
        "143f2f4f0", // current content-block header target
        "143f30bf0", // current ReadContentBlockPayload target
        "143f30e10", // current field header / payload target
        "143f3c090", // current RepLayout receive target
        "1444e4a40", // RepLayout receive/properties candidate from prior RE
        "140fa49e0", // ClientAckUpdateLevelVisibility registration
        "140fa52c0", // ServerUpdateLevelVisibility registration
        "144441e00", // ClientAckUpdateLevelVisibility exec/handler candidate
        "14444cfe0", // ServerUpdateLevelVisibility validate/handler candidate
        "143fb6800", // FNetLevelVisibilityTransactionId ops candidate
        "143febfd0"  // FUpdateLevelVisibilityLevelInfo ops candidate
    };

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : DEFAULT_OUT;
        new File(outDir).mkdirs();

        Set<String> targets = new LinkedHashSet<String>();
        if (args.length > 1) {
            for (int i = 1; i < args.length; ++i) {
                if (args[i] != null && !args[i].trim().isEmpty()) {
                    targets.add(args[i].trim());
                }
            }
        } else {
            for (String target : DEFAULT_TARGETS) targets.add(target);
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        AddressFactory af = currentProgram.getAddressFactory();
        Set<Function> funcs = new LinkedHashSet<Function>();
        PrintWriter summary = new PrintWriter(new FileWriter(new File(outDir, "summary.txt")));
        summary.println("program=" + currentProgram.getName());
        summary.println("image_base=" + currentProgram.getImageBase());
        summary.println("targets=" + targets);
        summary.println();

        for (String target : targets) {
            try {
                Address addr = af.getAddress(target);
                Function f = fm.getFunctionContaining(addr);
                if (f == null) f = fm.getFunctionAt(addr);
                summary.println("target " + target + " -> "
                    + (f == null ? "NO_FUNCTION" : (f.getEntryPoint() + " " + f.getName())));
                if (f != null) funcs.add(f);
            } catch (Exception e) {
                summary.println("target " + target + " -> ERROR " + e.getMessage());
            }
        }

        Set<Function> roots = new LinkedHashSet<Function>(funcs);
        for (Function f : roots) {
            try {
                for (Function caller : f.getCallingFunctions(monitor)) {
                    if (!caller.isExternal() && !caller.isThunk()) funcs.add(caller);
                }
                for (Function callee : f.getCalledFunctions(monitor)) {
                    if (!callee.isExternal() && !callee.isThunk()) funcs.add(callee);
                }
            } catch (Exception e) {
                summary.println("xref scan failed for " + f.getEntryPoint() + ": " + e.getMessage());
            }
        }
        summary.println();
        summary.println("functions_to_decompile=" + funcs.size());

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int done = 0;
        for (Function f : funcs) {
            if (monitor.isCancelled()) break;
            try {
                String va = f.getEntryPoint().toString();
                String name = f.getName();
                summary.println("function " + va + " " + name + " size=" + f.getBody().getNumAddresses());
                summary.println("  strings=" + stringsReferencedBy(f));
                summary.println("  callers=" + functionList(f.getCallingFunctions(monitor)));
                summary.println("  callees=" + functionList(f.getCalledFunctions(monitor)));

                DecompileResults res = dec.decompileFunction(f, 180, monitor);
                if (res != null && res.decompileCompleted()) {
                    String safe = safeFileName(va + "_" + name) + ".c";
                    PrintWriter out = new PrintWriter(new FileWriter(new File(outDir, safe)));
                    out.println("// DecompAoCTargets");
                    out.println("// program: " + currentProgram.getName());
                    out.println("// VA: " + va + " NAME: " + name + " size: " + f.getBody().getNumAddresses());
                    out.println("// strings: " + stringsReferencedBy(f));
                    out.println("// callers: " + functionList(f.getCallingFunctions(monitor)));
                    out.println("// callees: " + functionList(f.getCalledFunctions(monitor)));
                    out.println();
                    out.print(res.getDecompiledFunction().getC());
                    out.close();
                    done++;
                } else {
                    summary.println("  decompile_failed");
                }
            } catch (Exception e) {
                summary.println("  error=" + e.getMessage());
            }
        }
        dec.dispose();
        summary.println();
        summary.println("decompiled=" + done);
        summary.close();
        println("[DecompAoCTargets] wrote " + done + " functions to " + outDir);
    }

    private String functionList(Set<Function> funcs) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Function f : funcs) {
            if (f == null || f.isExternal()) continue;
            if (n++ > 0) sb.append(" ");
            sb.append(f.getEntryPoint()).append(":").append(f.getName());
            if (n >= 20) {
                sb.append(" ...");
                break;
            }
        }
        return sb.toString();
    }

    private String stringsReferencedBy(Function f) {
        StringBuilder sb = new StringBuilder();
        try {
            Listing listing = currentProgram.getListing();
            InstructionIterator insns = listing.getInstructions(f.getBody(), true);
            int n = 0;
            while (insns.hasNext() && n < 20) {
                Instruction insn = insns.next();
                for (Reference ref : insn.getReferencesFrom()) {
                    Data data = listing.getDataAt(ref.getToAddress());
                    if (data == null) continue;
                    StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
                    if (sdi == null) continue;
                    String value = sdi.getStringValue();
                    if (value == null || value.length() < 3 || value.length() > 120) continue;
                    if (sb.length() > 0) sb.append(" | ");
                    sb.append(value.replace('\n', ' '));
                    n++;
                }
            }
        } catch (Exception e) {
            return "ERROR " + e.getMessage();
        }
        return sb.toString();
    }

    private String safeFileName(String raw) {
        String safe = raw.replaceAll("[:<>\"/\\\\|?*]", "_");
        if (safe.length() > 140) safe = safe.substring(0, 140);
        return safe;
    }
}

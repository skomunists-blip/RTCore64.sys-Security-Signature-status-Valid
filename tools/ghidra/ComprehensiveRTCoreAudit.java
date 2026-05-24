import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ComprehensiveRTCoreAudit extends GhidraScript {
    private PrintWriter out;
    private DecompInterface decompiler;

    private final List<String> dangerousNames = Arrays.asList(
        "MmMapIoSpace", "MmUnmapIoSpace", "MmMapLockedPages", "MmMapLockedPagesSpecifyCache",
        "MmCopyMemory", "MmCopyVirtualMemory", "MmProbeAndLockPages", "IoAllocateMdl",
        "ZwMapViewOfSection", "ZwUnmapViewOfSection", "ZwOpenSection", "ObReferenceObjectByHandle",
        "HalTranslateBusAddress", "HalGetBusDataByOffset", "HalSetBusDataByOffset",
        "ZwCreateSection", "ZwOpenProcess", "ZwOpenThread", "PsLookupProcessByProcessId",
        "KeStackAttachProcess", "ProbeForRead", "ProbeForWrite", "ExGetPreviousMode",
        "WdmlibIoCreateDeviceSecure", "IoCreateDevice", "IoCreateDeviceSecure"
    );

    private final long[] ioctlConstants = new long[] {
        0x80002000L, 0x80002004L, 0x80002008L, 0x8000200cL, 0x80002010L,
        0x80002014L, 0x80002018L, 0x8000201cL, 0x80002028L, 0x8000202cL,
        0x80002030L, 0x80002034L, 0x80002040L, 0x80002044L, 0x80002048L,
        0x8000204cL, 0x80002050L, 0x80002054L
    };

    private void line(String s) {
        out.println(s);
    }

    private Function functionAt(String addressText) {
        return getFunctionAt(toAddr(addressText));
    }

    private String functionNameAt(Address address) {
        Function f = getFunctionContaining(address);
        return f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint();
    }

    private void printProgramSummary() {
        line("===== PROGRAM SUMMARY =====");
        line("Name=" + currentProgram.getName());
        line("Language=" + currentProgram.getLanguageID());
        line("CompilerSpec=" + currentProgram.getCompilerSpec().getCompilerSpecID());
        line("ImageBase=" + currentProgram.getImageBase());
        line("MinAddress=" + currentProgram.getMinAddress());
        line("MaxAddress=" + currentProgram.getMaxAddress());
        int count = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            it.next();
            count++;
        }
        line("FunctionCount=" + count);
        line("");
    }

    private void printImports() {
        line("===== IMPORTS / EXTERNAL SYMBOLS =====");
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol s = symbols.next();
            if (s.isExternal() || s.getSymbolType() == SymbolType.FUNCTION && s.getAddress().isExternalAddress()) {
                line(s.getName(true) + " @ " + s.getAddress());
            }
        }
        line("");
    }

    private void printDangerousRefs() {
        line("===== DANGEROUS API REFERENCES =====");
        for (String needle : dangerousNames) {
            boolean found = false;
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol s = symbols.next();
                if (!s.getName(true).toLowerCase().contains(needle.toLowerCase())) {
                    continue;
                }
                found = true;
                line("API=" + s.getName(true) + " Address=" + s.getAddress());
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    line("  FROM=" + r.getFromAddress() + " IN=" + functionNameAt(r.getFromAddress()) + " TYPE=" + r.getReferenceType());
                }
            }
            if (!found) {
                line("API=" + needle + " NOT_FOUND");
            }
        }
        line("");
    }

    private void printIoctlHits() {
        line("===== IOCTL CONSTANT HITS =====");
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String text = ins.toString().toLowerCase();
            for (long c : ioctlConstants) {
                String hex = "0x" + Long.toHexString(c);
                if (text.contains(hex)) {
                    line(ins.getAddress() + " " + ins + " IN=" + functionNameAt(ins.getAddress()));
                }
            }
        }
        line("");
    }

    private void printInterestingStrings() throws MemoryAccessException {
        line("===== INTERESTING UTF-16 STRING LOCATIONS =====");
        String[] values = new String[] {
            "\\Device\\PhysicalMemory", "\\Device\\RTCore64", "\\DosDevices\\RTCore64",
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        };
        for (String value : values) {
            Address found = findUtf16(value);
            line(value + " => " + (found == null ? "NOT_FOUND" : found.toString()));
        }
        line("");
    }

    private Address findUtf16(String value) throws MemoryAccessException {
        byte[] bytes = new byte[(value.length() + 1) * 2];
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            bytes[i * 2] = (byte)(c & 0xff);
            bytes[i * 2 + 1] = (byte)((c >> 8) & 0xff);
        }
        return currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), bytes, null, true, monitor);
    }

    private void printDefinedStrings() {
        line("===== DEFINED STRING DATA (BEST EFFORT) =====");
        int emitted = 0;
        for (Data data = currentProgram.getListing().getDefinedData(true).next(); data != null; ) {
            try {
                Object v = data.getValue();
                if (v != null) {
                    String s = v.toString();
                    if (s.length() >= 4 && (s.contains("\\") || s.toLowerCase().contains("rtcore") || s.contains("D:P("))) {
                        line(data.getAddress() + " " + s);
                        emitted++;
                    }
                }
                data = currentProgram.getListing().getDefinedDataAfter(data.getAddress());
            } catch (Exception e) {
                break;
            }
        }
        line("EmittedStringCount=" + emitted);
        line("");
    }

    private void printGlobalRefs() {
        line("===== IMPORTANT GLOBAL REFERENCES =====");
        String[][] globals = new String[][] {
            {"DAT_00014360_state", "00014360"},
            {"DAT_00014370_mapping_base_table", "00014370"},
            {"DAT_00014b70_mapping_size_table", "00014b70"}
        };
        for (String[] g : globals) {
            Address a = toAddr(g[1]);
            line("GLOBAL=" + g[0] + " Address=" + a);
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
            while (refs.hasNext()) {
                Reference r = refs.next();
                line("  FROM=" + r.getFromAddress() + " IN=" + functionNameAt(r.getFromAddress()) + " TYPE=" + r.getReferenceType());
            }
        }
        line("");
    }

    private void printAllFunctions() {
        line("===== ALL FUNCTIONS =====");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            line(f.getEntryPoint() + " " + f.getName() + " Body=" + f.getBody());
        }
        line("");
    }

    private void printCallGraph() {
        line("===== CALL REFERENCES BY FUNCTION =====");
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isExternal()) {
                continue;
            }
            Set<String> callees = new LinkedHashSet<>();
            InstructionIterator iit = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                if (!ins.getFlowType().isCall()) {
                    continue;
                }
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall()) {
                        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                        callees.add((s == null ? r.getToAddress().toString() : s.getName(true)) + "@" + r.getToAddress());
                    }
                }
            }
            line(f.getEntryPoint() + " " + f.getName() + " CALLS " + callees);
        }
        line("");
    }

    private void printMemoryDerefsNearDispatch() {
        line("===== MEMORY WRITE / PRIVILEGED INSTRUCTIONS IN DISPATCH RANGE =====");
        Address start = toAddr("00011438");
        Address end = toAddr("00011b20");
        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) {
                break;
            }
            String mnemonic = ins.getMnemonicString().toLowerCase();
            boolean interesting = mnemonic.equals("wrmsr") || mnemonic.equals("rdmsr") ||
                mnemonic.equals("out") || mnemonic.equals("in") ||
                mnemonic.equals("mov") && ins.getNumOperands() > 0 && OperandType.isAddress(ins.getOperandType(0));
            if (interesting) {
                line(ins.getAddress() + " " + ins + " IN=" + functionNameAt(ins.getAddress()));
            }
        }
        line("");
    }

    private void decompileFunction(String label, String addressText) {
        Function f = functionAt(addressText);
        line("===== DECOMPILE " + label + " " + addressText + " =====");
        if (f == null) {
            line("NO_FUNCTION");
            line("");
            return;
        }
        DecompileResults res = decompiler.decompileFunction(f, 60, monitor);
        if (!res.decompileCompleted()) {
            line("DECOMPILE_FAILED=" + res.getErrorMessage());
        } else {
            line(res.getDecompiledFunction().getC());
        }
        line("");
    }

    private void decompileAllNonExternal() {
        line("===== DECOMPILE ALL NON-EXTERNAL FUNCTIONS =====");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal()) {
                continue;
            }
            line("----- FUNCTION " + f.getName() + " @ " + f.getEntryPoint() + " -----");
            DecompileResults res = decompiler.decompileFunction(f, 45, monitor);
            if (res.decompileCompleted()) {
                line(res.getDecompiledFunction().getC());
            } else {
                line("DECOMPILE_FAILED=" + res.getErrorMessage());
            }
        }
        line("");
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "rtcore_comprehensive_audit.txt";
        File outFile = new File(outPath);
        out = new PrintWriter(outFile, "UTF-8");

        decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.openProgram(currentProgram);

        printProgramSummary();
        printImports();
        printDangerousRefs();
        printInterestingStrings();
        printDefinedStrings();
        printAllFunctions();
        printCallGraph();
        printGlobalRefs();
        printIoctlHits();
        printMemoryDerefsNearDispatch();
        decompileFunction("FUN_00011044_address_filter", "00011044");
        decompileFunction("FUN_00011150_physical_memory_map", "00011150");
        decompileFunction("FUN_00011384_mmio_map", "00011384");
        decompileFunction("FUN_00011438_device_control_dispatch", "00011438");
        decompileFunction("FUN_00011b30_driver_entry", "00011b30");
        decompileAllNonExternal();

        decompiler.dispose();
        out.flush();
        out.close();
        println("WROTE " + outFile.getAbsolutePath());
    }
}

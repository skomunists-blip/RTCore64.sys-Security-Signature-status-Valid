import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

public class DeepRTCoreIssueHunt extends GhidraScript {
    private PrintWriter out;
    private DecompInterface decompiler;

    private void line(String s) {
        out.println(s);
    }

    private String where(Address a) {
        Function f = getFunctionContaining(a);
        return f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint();
    }

    private void dumpRange(String title, String startText, String endText) {
        line("===== " + title + " " + startText + "-" + endText + " =====");
        Address start = toAddr(startText);
        Address end = toAddr(endText);
        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) {
                break;
            }
            line(ins.getAddress() + "  " + ins + "  ; " + where(ins.getAddress()));
        }
        line("");
    }

    private void decompile(String title, String addressText) {
        Function f = getFunctionAt(toAddr(addressText));
        line("===== DECOMPILE " + title + " " + addressText + " =====");
        if (f == null) {
            line("NO_FUNCTION");
            line("");
            return;
        }
        DecompileResults res = decompiler.decompileFunction(f, 60, monitor);
        if (res == null || !res.decompileCompleted()) {
            line("DECOMPILE_FAILED");
            line("");
            return;
        }
        line(res.getDecompiledFunction().getC());
        line("");
    }

    private void findImports(String... names) {
        line("===== IMPORT / SYMBOL PRESENCE CHECK =====");
        List<String> wanted = Arrays.asList(names);
        for (String name : wanted) {
            boolean found = false;
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol s = symbols.next();
                if (s.getName(true).toLowerCase().contains(name.toLowerCase())) {
                    found = true;
                    line(name + "=FOUND " + s.getName(true) + " @ " + s.getAddress());
                    ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
                    while (refs.hasNext()) {
                        Reference r = refs.next();
                        line("  REF_FROM=" + r.getFromAddress() + " TYPE=" + r.getReferenceType() + " IN=" + where(r.getFromAddress()));
                    }
                }
            }
            if (!found) {
                line(name + "=NOT_FOUND");
            }
        }
        line("");
    }

    private void printIoctlDecode() {
        line("===== IOCTL DECODE =====");
        long[] ioctls = new long[] {
            0x80002000L, 0x80002004L, 0x80002008L, 0x8000200cL, 0x80002010L,
            0x80002014L, 0x80002018L, 0x8000201cL, 0x80002028L, 0x8000202cL,
            0x80002030L, 0x80002034L, 0x80002040L, 0x80002044L, 0x80002048L,
            0x8000204cL, 0x80002050L, 0x80002054L
        };
        for (long code : ioctls) {
            long method = code & 3;
            long function = (code >> 2) & 0xfff;
            long access = (code >> 14) & 3;
            long device = (code >> 16) & 0xffff;
            line(String.format("0x%08X DeviceType=0x%X Function=0x%X Method=%d Access=%d", code, device, function, method, access));
        }
        line("Interpretation: all listed IOCTLs decode as METHOD_BUFFERED and FILE_ANY_ACCESS.");
        line("");
    }

    private void findInstructionText(String title, String... needles) {
        line("===== INSTRUCTION TEXT HITS: " + title + " =====");
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String text = ins.toString().toLowerCase();
            for (String needle : needles) {
                if (text.contains(needle.toLowerCase())) {
                    line(ins.getAddress() + "  " + ins + "  ; " + where(ins.getAddress()));
                    break;
                }
            }
        }
        line("");
    }

    private void refsTo(String title, String addressText) {
        Address a = toAddr(addressText);
        line("===== REFS TO " + title + " " + a + " =====");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
        while (refs.hasNext()) {
            Reference r = refs.next();
            line("FROM=" + r.getFromAddress() + " TYPE=" + r.getReferenceType() + " IN=" + where(r.getFromAddress()));
        }
        line("");
    }

    private void staticFindings() {
        line("===== DEEP STATIC FINDINGS / HUNT LIST =====");
        line("F1. FUN_00011384 full mapping-table failure path: after MmMapIoSpace succeeds, the code scans DAT_00014370 for a zero slot. If no zero slot exists, the loop exits at 0x100 and uVar3 is still set to STATUS_SUCCESS. No MmUnmapIoSpace rollback is visible. Impact: system VA/MMIO mapping leak and false success when the 256-entry table is full.");
        line("F2. DAT_00014370 / DAT_00014b70 have no visible locking. No spinlock, fast mutex, guarded mutex, ERESOURCE, or interlocked table protocol imports are present. Parallel DeviceIoControl calls can race map/unmap/read/write paths, creating use-after-unmap or stale-slot states.");
        line("F3. FUN_00011150 calls ObReferenceObjectByHandle on \\Device\\PhysicalMemory but no ObDereferenceObject import/call is present. The referenced object pointer is not used by ZwMapViewOfSection. This is a likely object-reference leak. Also, if ObReferenceObjectByHandle fails, the already-opened section handle is returned without ZwClose.");
        line("F4. Driver unload path deletes symbolic link/device but no table walk unmaps outstanding DAT_00014370 mappings. Active MmMapIoSpace mappings can survive as leaked system mappings if callers do not clean them.");
        line("F5. FUN_00011044 display BAR allow policy trusts class code 0x03 and BAR value, then grants BAR&0xFFFFFF00 through +16MiB. It does not query actual BAR size or CM resource descriptors. This can expose adjacent MMIO/device ranges inside the synthetic 16MiB window.");
        line("F6. FUN_00011044 uses 32-bit BAR arithmetic and truncates BAR-derived windows to uint32. This is not a proven bypass in the current VM, but it is a fragile boundary check for 64-bit or high BAR layouts.");
        line("F7. IOCTL 0x80002050 and 0x80002054 ignore HalGetBusDataByOffset/HalSetBusDataByOffset return counts. The driver reports STATUS_SUCCESS even if the HAL read/write touched fewer bytes than requested.");
        line("F8. Raw I/O port write guard blocks only exact port 0xCFC when CF8 selects BAR offsets 0x10-0x27. PCI config data window is byte-addressable at 0xCFC-0xCFF, and 0xCF8 address-selection writes remain a separate surface. Treat as bypass candidate only, not confirmed RAM R/W.");
        line("F9. MSR denylist blocks a few known-dangerous indices but leaves broad RDMSR/WRMSR exposed to elevated user-mode callers. This is a high-risk admin-to-kernel hardware-control surface and DoS class.");
        line("F10. Buffer-length policy remains input-length-centric in most branches. METHOD_BUFFERED mitigates direct SystemBuffer overrun for equal/greater input buffers, but output length is not consistently validated before IoStatus.Information is set.");
        line("");
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "rtcore_deep_issue_hunt.txt";
        out = new PrintWriter(new File(outPath), "UTF-8");

        decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.openProgram(currentProgram);

        line("RTCore64 deep static issue hunt");
        line("Program=" + currentProgram.getName());
        line("ImageBase=" + currentProgram.getImageBase());
        line("");

        printIoctlDecode();
        findImports(
            "ObReferenceObjectByHandle", "ObDereferenceObject",
            "KeAcquireSpinLock", "KeReleaseSpinLock", "ExAcquireFastMutex", "ExReleaseFastMutex",
            "ExInitializeResourceLite", "ExAcquireResourceExclusiveLite", "InterlockedCompareExchange",
            "MmMapIoSpace", "MmUnmapIoSpace", "ZwMapViewOfSection", "ZwUnmapViewOfSection",
            "HalGetBusDataByOffset", "HalSetBusDataByOffset", "HalTranslateBusAddress",
            "ProbeForRead", "ProbeForWrite", "ExGetPreviousMode"
        );

        refsTo("DAT_00014370 mapping base table", "00014370");
        refsTo("DAT_00014b70 mapping size table", "00014b70");

        dumpRange("FUN_00011384 MmMapIoSpace + table insert", "00011384", "0001142f");
        dumpRange("FUN_00011150 PhysicalMemory map / object reference path", "00011150", "0001137d");
        dumpRange("FUN_00011044 BAR allow window", "00011044", "00011146");
        dumpRange("FUN_00011008 unload cleanup", "00011008", "0001103d");
        dumpRange("IOCTL 0x80002050/54 PCI config read/write", "00011790", "00011870");
        dumpRange("MSR read/write branches", "00011a20", "00011ae8");

        findInstructionText("privileged instructions", "wrmsr", "rdmsr", "out ", "in ");
        findInstructionText("constants and risky arithmetic", "0x1000000", "0xffffff00", "0xf001f", "0x204", "0xcfc", "0xcf8");

        decompile("FUN_00011044_address_filter", "00011044");
        decompile("FUN_00011150_physical_memory_map", "00011150");
        decompile("FUN_00011384_mmio_map_table", "00011384");
        decompile("FUN_00011008_unload", "00011008");
        decompile("FUN_00011438_dispatch", "00011438");

        staticFindings();

        out.flush();
        out.close();
        println("WROTE " + outPath);
    }
}

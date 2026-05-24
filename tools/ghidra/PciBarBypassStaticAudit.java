import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.PrintWriter;

public class PciBarBypassStaticAudit extends GhidraScript {
    private PrintWriter out;

    private void line(String s) {
        out.println(s);
    }

    private String functionNameAt(Address a) {
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
            line(ins.getAddress() + "  " + ins + "  ; " + functionNameAt(ins.getAddress()));
        }
        line("");
    }

    private void findTextHits(String title, String... needles) {
        line("===== TEXT HITS " + title + " =====");
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String text = ins.toString().toLowerCase();
            for (String needle : needles) {
                if (text.contains(needle.toLowerCase())) {
                    line(ins.getAddress() + "  " + ins + "  ; " + functionNameAt(ins.getAddress()));
                    break;
                }
            }
        }
        line("");
    }

    private void printGlobalRefs(String label, String addressText) {
        Address address = toAddr(addressText);
        line("===== REFS TO " + label + " " + address + " =====");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
        while (refs.hasNext()) {
            Reference r = refs.next();
            line("FROM=" + r.getFromAddress() + " TYPE=" + r.getReferenceType() + " IN=" + functionNameAt(r.getFromAddress()));
        }
        line("");
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "rtcore_pci_bar_bypass_static.txt";
        out = new PrintWriter(new File(outPath), "UTF-8");

        line("RTCore64 PCI BAR bypass static audit");
        line("Purpose: identify whether raw I/O port write IOCTLs can bypass the PCI BAR write guard used by HalSetBusDataByOffset path.");
        line("");

        dumpRange("IOCTL 0x80002014 byte out guard", "00011500", "00011565");
        dumpRange("IOCTL 0x80002018 word out guard", "00011570", "000115b5");
        dumpRange("IOCTL 0x8000201c dword out guard", "000115c0", "00011610");
        dumpRange("IOCTL 0x80002054 HalSetBusDataByOffset guard", "000117a0", "00011880");
        dumpRange("FUN_00011044 PCI BAR allowlist filter", "00011044", "0001114f");

        findTextHits("PCI config ports and BAR masks", "0xcfc", "0xcf8", "0xffffff00", "0x1000000");
        findTextHits("privileged port and MSR ops", "out ", "in ", "wrmsr", "rdmsr");

        printGlobalRefs("DAT_00014370 mapping base table", "00014370");
        printGlobalRefs("DAT_00014b70 mapping size table", "00014b70");

        line("===== STATIC INTERPRETATION CHECKLIST =====");
        line("1. Raw I/O write branches check exact port 0xCFC before denying writes to PCI BAR offsets.");
        line("2. PCI config data window consists of byte ports 0xCFC-0xCFF; exact-port-only checks may leave partial writes via 0xCFD/0xCFE/0xCFF.");
        line("3. Raw write branches also permit writes to 0xCF8 unless another caller-side policy blocks them; this changes PCI config address selection.");
        line("4. HalSetBusDataByOffset IOCTL 0x80002054 blocks BAR offsets 0x10-0x27, but raw port writes are a separate path.");
        line("5. This is a bypass candidate, not a confirmed RAM read/write primitive without dynamic proof.");

        out.flush();
        out.close();
        println("WROTE " + outPath);
    }
}

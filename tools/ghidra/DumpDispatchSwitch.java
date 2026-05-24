import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.File;
import java.io.PrintWriter;

public class DumpDispatchSwitch extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "rtcore_dispatch_switch_listing.txt";
        PrintWriter out = new PrintWriter(new File(outPath), "UTF-8");
        Address start = toAddr("00011470");
        Address end = toAddr("00011690");
        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) break;
            out.println(ins.getAddress() + "  " + ins);
        }
        out.flush();
        out.close();
        println("WROTE " + outPath);
    }
}

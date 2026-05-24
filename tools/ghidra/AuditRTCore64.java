import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class AuditRTCore64 extends GhidraScript {
    private Function findTarget(String addressText) throws Exception {
        Address addr = toAddr(addressText);
        Function direct = getFunctionAt(addr);
        if (direct != null) {
            return direct;
        }

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String name = f.getName();
            if (name.equals("FUN_" + addressText) || name.endsWith(addressText.substring(addressText.length() - 4))) {
                return f;
            }
        }

        return null;
    }

    private void decompileAndPrint(String addressText, DecompInterface decompiler) throws Exception {
        Function target = findTarget(addressText);
        if (target == null) {
            println("TARGET_NOT_FOUND: " + addressText);
            return;
        }

        println("Target function: " + target.getName() + " @ " + target.getEntryPoint());
        DecompileResults results = decompiler.decompileFunction(target, 120, monitor);

        if (!results.decompileCompleted()) {
            println("DECOMPILE_FAILED " + addressText + ": " + results.getErrorMessage());
            return;
        }

        println("===== DECOMPILED_C_BEGIN " + addressText + " =====");
        println(results.getDecompiledFunction().getC());
        println("===== DECOMPILED_C_END " + addressText + " =====");
    }

    @Override
    public void run() throws Exception {
        println("Program: " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        decompileAndPrint("00011044", decompiler);
        decompileAndPrint("00011150", decompiler);
        decompileAndPrint("00011384", decompiler);
        decompileAndPrint("00011438", decompiler);
        decompileAndPrint("00011b30", decompiler);
    }
}

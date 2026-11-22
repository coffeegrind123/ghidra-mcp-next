// Renames the function at the first argument.
// @category Test
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class RenameFirst extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        var f = getFunctionAt(toAddr(a[0]));
        f.setName(a[1], SourceType.USER_DEFINED);
        println("renamed " + f.getEntryPoint());
        if (a.length > 2) { throw new Exception("boom"); }
    }
}

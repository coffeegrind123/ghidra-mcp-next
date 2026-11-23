# Renames the function at the first argument, then fails.
# @category Test
from ghidra.program.model.symbol import SourceType

args = getScriptArgs()  # noqa: F821 -- GhidraScript global
func = getFunctionAt(toAddr(args[0]))  # noqa: F821
func.setName(args[1], SourceType.USER_DEFINED)
raise RuntimeError("boom after rename")

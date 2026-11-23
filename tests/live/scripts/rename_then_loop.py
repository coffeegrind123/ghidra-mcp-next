# Renames the function at the first argument, then never finishes.
# @category Test
from ghidra.program.model.symbol import SourceType

args = getScriptArgs()  # noqa: F821 -- GhidraScript global
getFunctionAt(toAddr(args[0])).setName(args[1], SourceType.USER_DEFINED)  # noqa: F821
while True:
    pass

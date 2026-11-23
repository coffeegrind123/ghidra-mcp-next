# re-mcp-core

Supervisor and transport layer of [ghidra-mcp-next](https://github.com/coffeegrind123/ghidra-mcp-next):
worker pool (one Ghidra worker process per database), routing tools and resources to
workers, the meta tools (`search_tools`, `get_schema`, `call`, `batch`, `execute`), the
persistent HTTP daemon with its stdio proxy, and shared helpers.

Not used on its own: install `re-mcp-ghidra`, which provides the server. See the
[main README](https://github.com/coffeegrind123/ghidra-mcp-next#readme).

## License

Dual-licensed under [MIT](../../LICENSES/MIT.txt) and [Apache-2.0](../../LICENSES/Apache-2.0.txt).

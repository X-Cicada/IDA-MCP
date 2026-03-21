# Repository Guidelines

## Project Map
```text
IDA-MCP/
├── ida_mcp.py                  # IDA plugin entrypoint; starts/stops per-instance MCP and registers with gateway
├── command.py                  # CLI for gateway status, tool calls, resource reads, and open_in_ida
├── install.py                  # Installer and interactive config writer
├── ida_mcp/
│   ├── config.py               # Loads config.conf and exposes runtime settings
│   ├── config.conf             # User-editable transport and launch configuration
│   ├── rpc.py                  # @tool / @resource / @unsafe registration
│   ├── sync.py                 # IDA thread synchronization helpers
│   ├── utils.py                # Shared parsing, paging, and filter utilities
│   ├── compat.py               # IDA 8.x/9.x compatibility layer
│   ├── server_factory.py       # Builds the FastMCP server inside IDA
│   ├── registry.py             # Gateway process startup and instance registration helpers
│   ├── registry_server.py      # Standalone gateway HTTP/internal server
│   ├── runtime.py              # Optional proxy startup helpers
│   ├── control.py              # Client-facing control wrappers used by command.py
│   ├── api_core.py             # Metadata, functions, globals, strings, imports/exports
│   ├── api_analysis.py         # Decompile, disasm, xrefs, search, basic blocks
│   ├── api_memory.py           # Raw bytes, scalars, strings
│   ├── api_types.py            # Type, struct, enum, typedef operations
│   ├── api_modify.py           # Comments, renames, byte patches
│   ├── api_modeling.py         # Create/delete functions and convert code/data/string
│   ├── api_stack.py            # Stack-frame and local-variable operations
│   ├── api_debug.py            # Unsafe debugger controls
│   ├── api_python.py           # Unsafe Python execution in IDA
│   ├── api_lifecycle.py        # Close/shutdown inside an IDA process
│   ├── api_resources.py        # ida:// resource endpoints for direct instance access
│   └── proxy/
│       ├── register_tools.py   # Proxy-side tool registration exposed to MCP clients
│       ├── lifecycle.py        # open_in_ida, staging, and WSL/Windows path bridge
│       ├── _http.py            # Gateway HTTP request helpers
│       ├── _state.py           # Selected-instance state and validation
│       ├── _server.py          # Shared FastMCP proxy server
│       ├── http_server.py      # HTTP transport wrapper for proxy server
│       └── ida_mcp_proxy.py    # Stdio proxy entrypoint
├── test/
│   ├── test.py                 # Wrapper around pytest with marker and transport selection
│   ├── conftest.py             # Shared fixtures and transport setup
│   ├── test_*.py               # Feature-specific pytest modules
│   └── samples/                # Binary/source fixtures used by tests
├── README.md                   # English user/developer documentation
├── README_CN.md                # Chinese user/developer documentation
├── API.md                      # Tool and response contract reference
├── pytest.ini                  # Pytest markers and defaults
└── requirements.txt            # Python dependencies for IDA-side environment
```

## Build, Test, and Development Commands
Install dependencies into the IDA Python environment:

```bash
python install.py
```

Run the default test suite through the project wrapper:

```bash
python test/test.py
python test/test.py --lifecycle
python test/test.py --transport=http --analysis
```

Run pytest directly when needed:

```bash
pytest -m "core or analysis"
pytest --transport=both test/test_lifecycle.py
```

## Coding Style & Naming Conventions
Use Python with 4-space indentation and type hints where practical. Follow existing naming: `snake_case` for functions and modules, `UPPER_CASE` for constants, `Test*` classes and `test_*` functions for tests. Keep helpers small and explicit; this repo favors straightforward control flow over abstraction-heavy patterns. There is no enforced formatter in-tree, so match surrounding style closely.

## Testing Guidelines
Tests use `pytest` with markers defined in [`pytest.ini`](/mnt/e/DM/IDA-MCP/pytest.ini), including `core`, `analysis`, `resources`, and `lifecycle`. Add tests next to the affected area and mark them with the appropriate module marker. For lifecycle or gateway changes, run `python test/test.py --lifecycle`; for focused work, run the relevant marker or file directly. Avoid tests that launch real processes unless explicitly intended.

## Commit & Pull Request Guidelines
Recent commits use short, imperative subjects such as `Add explicit WSL path bridge for open_in_ida` and `Refine open_in_ida launch flow and remove redundant tools`. Keep commit messages concise and action-oriented. PRs should describe behavior changes, list affected modules, note config or transport implications, and include exact test commands run. Add screenshots only for UI- or IDA-interaction changes where logs are insufficient.

## Security & Configuration Tips
Treat `py_eval` and all `dbg_*` tools as unsafe. Document any changes to `config.conf`, especially transport flags, ports, and `wsl_path_bridge`. When touching `open_in_ida`, verify both direct-path and staged launch behavior.

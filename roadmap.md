# IDA-MCP Roadmap

## Background

IDA-MCP already covers the main daily workflow surface: core reads, decompilation/disassembly, cross-references, memory reads, renaming/comments, stack editing, type application, database shaping, debugger control, and `py_eval`.

That means the roadmap should not be a growing checklist of small tools. Its job is to identify the remaining high-value gaps where users still reach for `py_eval`, then fill only those gaps with stable MCP APIs.

## Principles

- Prefer precise tools over many tools.
- Add a first-class tool only when existing tools cannot express the workflow cleanly.
- Prefer structured, machine-friendly output over string scraping or UI-coupled behavior.
- Keep proxy and direct-instance parameter names aligned.
- Treat MCP Resources as a stable read-only context surface for direct instance access, not as a proxy-parity target or a replacement for the full tool surface.
- Every addition must ship with proxy exposure, README/README_CN updates, and tests.

## Current Focus

The current priority is to reduce recurring `py_eval` usage without expanding the tool surface unnecessarily.

The main remaining gaps are:

- Structured analysis outputs that are still easier to obtain through ad hoc IDAPython than through stable JSON tools.
- A small number of high-value type-editing workflows that existing tools cannot model cleanly.
- Better composition and return structure for existing capabilities where that removes the need for custom scripting.

Already-shipped capabilities such as function creation/deletion, code/data/string creation, arrays, and undefine operations are baseline functionality, not future roadmap items.

## Phase 1: Structured Analysis

Goal: replace common string scraping and analysis-oriented `py_eval` snippets with a compact set of structured outputs.

Priority areas:

- Function-level caller and callee relationships.
- Structured function signature extraction.
- Structured pseudocode views when the Hex-Rays API can provide stable results.
- CFG output that is machine-friendly and consistent with existing basic-block data.

Acceptance criteria:

- The recommended path for common analysis automation is JSON output from dedicated tools, not parsing free-form text.
- New outputs compose cleanly with existing `decompile`, `disasm`, `xrefs_*`, and `get_basic_blocks` tools.
- No new analysis tool is added if the same workflow can be handled by improving the structure of an existing result.

## Phase 2: Minimal Type-Editing Additions

Goal: cover the few type-editing workflows that still require handwritten IDAPython, without turning the API into a CRUD matrix.

Priority areas:

- Explicit struct/enum/typedef declaration tools where the object being edited is clear from the tool name.
- Stable results that report whether the target already existed and whether the database changed.

Acceptance criteria:

- High-frequency type-editing tasks can be completed without `py_eval`.
- The API stays compact; avoid adding one tool per tiny operation unless that operation is clearly irreducible.
- Avoid catch-all declaration tools that accept arbitrary C text without a clear target kind.

## Phase 3: Product-Level Expansion

Goal: keep near-term MCP work focused, and reserve broader product scope for clearly separate milestones.

Longer-term directions already aligned with the README:

- Add a UI layer.
- Support internal model calls.
- Add multi-agent A2A automated reverse engineering after LangChain 1.0.0 is ready.

These are product-level initiatives, not justification for near-term MCP tool growth.

## Exit Criteria

This roadmap is succeeding when:

- common IDA automation uses a small set of dedicated MCP tools plus existing composable primitives;
- `py_eval` is mostly a fallback for edge cases, not the default path for routine workflows; and
- the API surface remains intentionally compact instead of expanding into overlapping micro-tools.

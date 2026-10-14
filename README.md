---
name: exe-extractor
description: Extract structural intelligence from Windows PE32+ executables — exports, imports, sections, CodeView PDB info with pre-built Microsoft Symbol Server URLs, embedded Authenticode signatures (PKCS#7 cert chain), Control Flow Guard (CFG) valid-call-target lists, Load Config (SecurityCookie + GuardCF pointers), x64 exception unwind tables, and resources. Built around and reverse-engineered from ntoskrnl.exe (the Windows NT kernel — PE32+, NATIVE subsystem, 34 sections, 3,298 kernel exports, 19 imported DLLs, an embedded Microsoft Authenticode signature, and 8,295 CFG-protected indirect call targets). Works on any PE file (.exe / .sys / .dll / .mun / .mui / .scr / .efi). Use this skill whenever the user mentions a Windows .exe or .sys file and wants to introspect its structure ("what does ntoskrnl.exe export", "what DLLs does this driver import", "what's the PDB GUID for this binary", "is this file signed", "extract the Authenticode cert chain", "what are the CFG targets", "list all kernel exports"), or wants a client-side visual browser for PE executable structure (as opposed to mun-extractor which is for resource-only binaries).
license: MIT
---

# exe extractor — PE32+ introspection for Windows executables

A PE executable is far more than its resources. For `ntoskrnl.exe` — the
Windows NT kernel — the `.rsrc` section is **243 KB out of 12 MB** (2%). The
interesting data is everywhere else: the **3,298 kernel exports** drivers
call into (`KeWaitForSingleObject`, `NtCreateFile`, `MmAllocateContiguousMemory`,
…), the **19 imported DLLs** (BOOTVID.dll, PSHED.dll, kdcom.dll, CI.dll, cng.sys,
msrpc.sys, plus a swarm of `ext-ms-win-ntos-*` API-set stub DLLs), the
**CodeView debug record** pointing at `ntkrnlmp.pdb` with a specific GUID+age
for one-click Microsoft Symbol Server lookup, the **embedded Authenticode
signature** (a 9.6 KB PKCS#7 whose certificate chain ends at the Microsoft Root
Certificate Authority 2010), the **8,295 Control Flow Guard** valid indirect
call targets in the `GFIDS` section, the **38,877 RUNTIME_FUNCTION** x64 unwind
entries in `.pdata`, and the **34 sections** themselves — including kernel-specific
ones like `PAGE`, `PAGELK`, `PAGEKD`, `POOLCODE`, `KVASCODE`, `RETPOL`, `INITKDBG`
that you simply do not see in user-mode binaries.

This skill extracts all of that — every byte of intelligence an analyst needs
to understand an opaque executable WITHOUT disassembling it. It is the
executable-side counterpart to `mun-extractor` (which mines resource-only
binaries): same proven PE parser, same in-browser philosophy, but the lens
shifts from "what pictures and icons are inside this file" to "what API does
this binary expose, what does it depend on, who signed it, and what security
mitigations does it have".

It was reverse-engineered from `ntoskrnl.exe` (Win11 10.0.22621.4319) —
every number in the table below was cross-validated against both the bundled
Python extractor and the bundled HTML extractor.

## Core knowledge: PE32+ in 60 seconds

1. **Parse the PE header.** DOS header `e_lfanew` at 0x3C → PE sig → COFF →
   optional header. Magic `0x20B` = PE32+ (x64), `0x10B` = PE32 (x86).
2. **PE32+ vs PE32 differences that matter**:
   - Optional header is 240 bytes (vs 224 for PE32).
   - ImageBase, SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit are u64
     (vs u32 in PE32).
   - Data directories start at offset 112 (vs 96 in PE32).
   - Import Lookup Table entries are 8 bytes (vs 4 in PE32) — high bit is
     bit 63, not bit 31.
3. **The 16 data directories** tell you what's in the binary:
   `[0]Export, [1]Import, [2]Resource, [3]Exception, [4]Security, [5]BaseReloc,
   [6]Debug, [7]Arch, [8]GlobalPtr, [9]TLS, [10]LoadConfig, [11]BoundImport,
   [12]IAT, [13]DelayImport, [14]COM, [15]Reserved`. For ntoskrnl.exe the
   populated ones are Export (107 KB), Import (400 B), Resource (239 KB),
   Exception (456 KB), Security (9.4 KB), BaseReloc (22.5 KB), Debug (112 B),
   LoadConfig (320 B), IAT (1.6 KB) — nine of sixteen.
4. **The Security directory is the documented exception**: its "VirtualAddress"
   field is actually a **file offset**, not an RVA. Misunderstanding this is
   the #1 bug in PE parsers that try to read Authenticode signatures.
5. **Sections can be tagged NOT_PAGED** (0x08000000) — kernel sections that
   must remain resident in physical memory at all IRQLs. User-mode binaries
   never have this flag; ntoskrnl.exe sets it on `.rdata`, `.pdata`, `.idata`,
   `PROTDATA`, `KVASCODE`, `RETPOL`, `TRACESUP`, `MINIEX`, `INITKDBG`. See
   `references/kernel-sections.md`.

## What each data directory gives you

### [0] Export — the API surface

For ntoskrnl.exe: **3,298 exported symbols** (`AlpcCreateSecurityContext`,
`IoCreateDevice`, `KeWaitForSingleObject`, `ZwCreateFile`, `MmAllocateContiguousMemory`,
…). Layout: an `IMAGE_EXPORT_DIRECTORY` at the directory's RVA points at three
parallel arrays — **AddressOfFunctions** (RVAs to function bodies),
**AddressOfNames** (RVAs to null-terminated strings), and
**AddressOfNameOrdinals** (u16 indices into the first array). A name → function
lookup goes: name in AddressOfNames[i] → ordinal in AddressOfNameOrdinals[i] →
function RVA in AddressOfFunctions[ordinal].

By convention, Windows kernel exports are prefixed by the manager that owns
them (`Ke*` = kernel, `Mm*` = memory manager, `Io*` = I/O, `Ps*` = process,
`Se*` = security, `Zw*`/`Nt*` = system services, `Ex*` = executive,
`Rt*` = runtime, `Fs*` = filesystem runtime, `Po*` = power, `Cc*` = cache,
`Ob*` = object manager, `Hv*` = hive/registry, `Kd*` = kernel debugger,
`Tm*` = transaction manager, `Wmi*`/`Et*` = tracing, `Alpc*`/`Lpc*` = LPC).
The bundled extractor groups exports by prefix — for ntoskrnl.exe the top 10
are: `Rt` 529, `Io` 360, `Ke` 285, `Zw` 260, `Ex` 238, `Fs` 229, `Ps` 204,
`Mm` 129, `Se` 115, `Nt` 113.

### [1] Import — what the binary depends on

For ntoskrnl.exe: **19 imported DLLs** totaling 182 functions. The kernel
imports from a small set of boot-time and HAL-side modules:
- `BOOTVID.dll` (11 funcs) — boot video driver (`VidInitialize`, `VBitBlt`, `VidDisplayString` for the blue boot logo)
- `PSHED.dll` (27 funcs) — Platform-Specific Hardware Error Driver (WHEA)
- `kdcom.dll` (5 funcs) — kernel debugger serial transport (`KdSendPacket`, `KdReceivePacket`)
- `CI.dll` (1 func) — Code Integrity (`CiInitialize` — the boot-time code-signing enforcement)
- `cng.sys` (1 func) — Cryptography Next Generation (`BCryptExportKey`)
- `msrpc.sys` (7 funcs) — Marshal/NDR runtime for in-kernel RPC
- `ext-ms-win-fs-clfs-l1-1-0.dll` (22 funcs) — Common Log File System
- `ext-ms-win-ntos-tm-l1-1-0.dll` (76 funcs) — Kernel Transaction Manager
- Plus a swarm of `ext-ms-win-ntos-*` API-set stub DLLs that resolve to
  the actual implementation at runtime via the API-set schema.

The Imports tab in the HTML extractor shows every DLL and every function it
imports, with IAT RVAs for cross-referencing.

### [4] Security — Authenticode signature

For ntoskrnl.exe: **9,672 bytes** of embedded PKCS#7 signature. Layout:
- 8-byte `WIN_CERTIFICATE` header: u32 length, u16 revision (0x0200 = WIN_CERT_REVISION_2_0), u16 cert_type (0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA)
- Followed by a DER-encoded PKCS#7 SignedData structure containing:
  - The signer's certificate (leaf)
  - Intermediate CA certificates
  - CRLs and optionally a RFC 3161 timestamp countersignature
  - The message digest (SHA-256 of the file's image hash, excluding the Security directory itself)

For ntoskrnl.exe the extracted certificate chain is:
- `Microsoft Windows` (leaf, signed 2025-06-19, expires 2026-06-17)
- ← `Microsoft Windows Production PCA 2011` (intermediate)
- ← `Microsoft Root Certificate Authority 2010` (root, trusted by Windows)
- Plus a separate RFC 3161 timestamp chain: `Microsoft Time-Stamp Service` ← `Microsoft Time-Stamp PCA 2010` ← `Microsoft Root Certificate Authority 2010`

The extractor dumps the raw PKCS#7 as a `.p7b` file for offline inspection with
`openssl pkcs7 -inform DER -in file.p7b -print_certs`, and also does a
browser-side ASN.1 walk to extract the certificate subjects on the fly.

### [6] Debug — CodeView PDB info

For ntoskrnl.exe: a single `IMAGE_DEBUG_TYPE_CODEVIEW` (type 2) entry pointing
at an `RSDS` record. Layout: 4-byte sig 'RSDS', 16-byte GUID, u32 age,
null-terminated PDB path. For ntoskrnl.exe:
- PDB filename: `ntkrnlmp.pdb`
- GUID: `7D91B8E878B8A42A1B9BFAB4FDC727BD`
- Age: `1`
- Pre-built Symbol Server URL: `https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/7D91B8E878B8A42A1B9BFAB4FDC727BD1/ntkrnlmp.pdb`

The HTML extractor's PDB tab shows these fields with a clickable URL — click
to download the matching PDB from Microsoft's public symbol server. Note that
the PDB file (`ntkrnlmp.pdb`) is NOT inside the .exe — only the GUID+age that
identifies which PDB to fetch.

The `mp` suffix in `ntkrnlmp.pdb` indicates a **multi-processor** (SMP) kernel
build. The single-processor build would be `ntoskrnl.pdb`, and the 4-GB-tuned
build would be `ntkrnlpa.pdb`. Modern Windows always ships the SMP build.

### [10] Load Config — security policy

For ntoskrnl.exe: a 320-byte `IMAGE_LOAD_CONFIG_DIRECTORY` containing:
- `SecurityCookie` at offset 0x58 — the address of the `__security_cookie`
  symbol used by `/GS` stack-canary checks. Randomized at boot.
- `GuardCFCheckFunctionPointer` at offset 0x70 — pointer to the CFG check
  function. Indirect calls are routed through this pointer; if the target is
  not in the GuardCFFunctionTable, the check fails fast (UNWIND/BREAK).
- `GuardCFDispatchFunctionPointer` at offset 0x78 — pointer to the CFG
  dispatch function (delay-load CFG).
- `GuardCFFunctionTable` at offset 0x80 — RVA of the CFG valid-call-target
  table (the GFIDS section in ntoskrnl.exe).
- `GuardCFFunctionCount` at offset 0x88 — count of entries in that table
  (8,295 for ntoskrnl.exe).

### [3] Exception — x64 unwind tables

For ntoskrnl.exe: **38,877 `RUNTIME_FUNCTION` entries** in `.pdata`. Each is
12 bytes: u32 start_rva, u32 end_rva, u32 unwind_info_rva. The unwind info
contains the prologue/epilogue opcodes that the kernel's SEH dispatcher uses
to unwind the stack during exception handling. The count (38,877) is much
larger than the export count (3,298) — most kernel functions are internal and
not exported, but every function with a stack frame has a .pdata entry.

### [2] Resource — minor for kernel binaries

For ntoskrnl.exe: only **10 resource leaves** total — 7 BITMAPs (the boot
splash / system icons used during early boot before user-mode is up), 1
RCDATA (`FUNCTIONEXTENTLIST` — a kernel-internal data table), 1 MESSAGETABLE
(system error strings), 1 VERSION. This is tiny compared to the 3,179
resources inside `imageres.dll.mun` — the kernel just doesn't ship art.
Use `mun-extractor` for files where resources are the point.

## The 34 sections of ntoskrnl.exe (annotated)

| Section | Flags | Purpose |
|---|---|---|
| `.rdata` | READ, NOT_PAGED | read-only data: constants, string literals, vtables, the rich header, IAT |
| `.pdata` | READ, NOT_PAGED | x64 exception unwind table (38,877 RUNTIME_FUNCTION entries) |
| `.idata` | READ, NOT_PAGED | import directory (small — kernel imports from very few DLLs) |
| `.edata` | READ | export directory (3,298 kernel exports) |
| `PROTDATA` | READ, NOT_PAGED | protected data (CFG-protected read-only globals) |
| `GFIDS` | READ, DISCARDABLE | **Control Flow Guard** valid-call-target bitmap |
| `Pad1` | (padding) | alignment padding to a 0x10000 boundary |
| `.text` | EXECUTE, READ | main kernel code — most exports live here |
| `PAGE` | EXECUTE, READ | pageable kernel code (can be paged out at low IRQL) |
| `PAGELK` | EXECUTE, READ | locked pageable code (must remain resident when locked) |
| `POOLCODE` | EXECUTE, READ | special pool code (driver verifier code paths) |
| `PAGEKD` | EXECUTE, READ | pageable code that only runs at PASSIVE_LEVEL |
| `PAGEVRFY` | EXECUTE, READ | driver verifier code paths |
| `PAGEHDLS` | EXECUTE, READ | pageable handler code |
| `PAGEBGFX` | EXECUTE, READ | boot graphics code |
| `TRACESUP` | EXECUTE, READ, NOT_PAGED | trace support code |
| `PAGECMRC` | EXECUTE, READ | commerce-related pageable code |
| `KVASCODE` | EXECUTE, READ, NOT_PAGED | KASLR support code (must stay resident — runs at high IRQL) |
| `RETPOL` | EXECUTE, READ, NOT_PAGED | retpoline mitigation code (Spectre v2 indirect-branch protection) |
| `INITKDBG` | EXECUTE, READ, NOT_PAGED | kernel debugger init code (thrown away after boot) |
| `MINIEX` | EXECUTE, READ | mini-executive code (early boot) |
| `INIT` | EXECUTE, READ | init code (thrown away after boot) |
| `.data` | READ, WRITE | writable data — globals, the security cookie, system state |
| `ALMOSTRO` | READ, WRITE | "almost read-only" data — becomes read-only after boot |
| `CACHEALI` | READ, WRITE | cache-aligned data (perf-critical globals) |
| `PAGEDATA` | READ, WRITE | pageable writable data |
| `PAGEVRFD` | READ, WRITE | driver verifier pageable data |
| `INITDATA` | READ | init data (thrown away after boot) |
| `CFGRO` | READ, NOT_PAGED | Control Flow Guard read-only bitmap |
| `.rsrc` | READ | resource section (10 leaves for ntoskrnl.exe) |
| `.reloc` | READ | base relocation table (applied if kernel cannot be loaded at its preferred base) |

The `Pad2`/`Pad3`/`Pad4` sections are pure alignment padding to bring
subsequent sections onto 0x10000 / 0x100000 boundaries.

## Workflow — pick a route

### Route A: the user wants to introspect an exe themselves → hand them the tool

`assets/extractor.html` is a standalone, dependency-free, fully client-side
HTML page. Copy it anywhere (or serve it via GitHub Pages — an `index.html`
twin works), open it in any modern browser (works offline, `file://` is fine),
drop the `.exe`/`.sys`/`.dll`/`.mun` on it. It:

* parses the PE header (machine, subsystem, timestamp, image base, entry
  point, data directories),
* shows a top-line KPI strip (sections / exports / imports / CFG targets /
  exceptions / resources),
* offers 9 tabs: **PE Header** (data directories table), **Sections** (all
  sections with their flags), **Exports** (searchable + filterable + prefix
  chips — virtualized for files with thousands of exports), **Imports**
  (per-DLL function tree), **PDB** (CodeView GUID + age + clickable
  Symbol-Server URL), **Authenticode** (PKCS#7 metadata + ASN.1 cert-chain
  walk + raw .p7b download), **CFG Targets** (Load Config + first 50 valid
  call targets + JSON download), **Exceptions** (first 50 RUNTIME_FUNCTION
  entries + JSON download), **Resources** (same 3-level resource tree walk
  as mun-extractor, for the few PEs that have meaningful resources).

Nothing is uploaded anywhere. Drop it on `file://` and it still works.

### Route B: headless extraction / automation → run the scripts

```bash
pip install pefile
python scripts/extract_exe_intel.py <file.exe|file.sys|file.dll> [out_dir]
```

`extract_exe_intel.py` writes:
- `pe_header.json` (machine, subsystem, image base, etc.)
- `sections.json` (all sections with decoded flag names)
- `exports.json` (full export table: name, ordinal, RVA, VA)
- `exports_by_prefix.json` (top 20 prefixes by count)
- `imports.json` (per-DLL function lists with IAT RVAs)
- `pdb.json` (CodeView PDB filename + GUID + age + symbol-server URL)
- `authenticode.json` + `authenticode.p7b` (raw PKCS#7 DER for openssl)
- `load_config.json` (SecurityCookie + GuardCF pointers + count)
- `cfg_targets.json` (full list of valid indirect call targets with flag bits)
- `exception_table.json` (full RUNTIME_FUNCTION list)
- `resources.json` (resource tree inventory + raw payloads saved as `.bin`/`.png`/etc.)
- `inventory.json` (master summary)

This is the path to use when scripting bulk analysis over a directory of
drivers or DLLs — the JSON output is stable and machine-parseable.

### Route C: disassembly / deep RE → other tools

This skill extracts PE-level structure only. To go deeper (read the actual
instructions of an exported function, recover local variables, follow call
graphs), use:

- **Microsoft Visual Studio + WinDbg** with the PDB fetched from the
  Symbol Server URL the extractor prints. Best-in-class for ntoskrnl.exe
  since Microsoft publishes kernel PDBs.
- **IDA Pro / Ghidra / Binary Ninja** with the PDB auto-loaded. All three
  can ingest the PDB you downloaded via the extractor's symbol-server URL.
- **`pe-bear` / `CFF Explorer`** for interactive PE inspection (Windows-only).
- **`dumpbin /exports /imports /headers`** (Visual Studio command line)
  for quick textual dumps.

## Verification standard — what counts as "extracted correctly"

Three checks, all cheap:

1. **Number agreement**: the HTML extractor's KPI strip and the Python
   extractor's `inventory.json` must report identical counts for sections,
   exports, imports, CFG targets, exceptions, and resources. For
   ntoskrnl.exe (Win11 10.0.22621.4319): **34 sections, 3,298 exports,
   19 imported DLLs, 8,295 CFG targets, 38,877 exception entries, 10
   resources** — both tools, identical.
2. **PDB GUID agreement**: the GUID the HTML extractor prints must match
   the GUID the Python extractor prints, and both must work as a
   Microsoft Symbol Server path component (i.e. fetching the URL must
   download a valid PDB).
3. **Cert chain agreement**: the certificate subjects the HTML extractor
   extracts in-browser must be a subset of what `openssl pkcs7 -inform DER
   -in authenticode.p7b -print_certs` reports. (The in-browser parser is
   intentionally minimal — it only walks ASN.1 string fields. For full
   certificate details — issuer/subject/validity/serial/extensions — use
   openssl on the downloaded `.p7b`.)

## Pitfalls register (each one cost real debugging time)

- **The Security directory uses a FILE OFFSET, not an RVA.** Every other
  data directory uses an RVA that you convert to a file offset via the
  section table. The Security directory is the documented exception —
  its VirtualAddress field is directly a file offset. If you treat it as
  an RVA and run it through `rva2off()`, you get garbage.
- **PE32+ Import Lookup Table entries are 8 bytes, not 4.** The high bit
  that marks "import by ordinal" is bit 63, not bit 31. Mixing this up
  makes every PE32+ import look like an ordinal import, and your import
  table comes out as a list of small numbers instead of function names.
- **JavaScript Number can't safely represent 64-bit values** above
  2^53. For PE32+ import entries (where you need to test bit 63), use
  BigInt throughout the import-walk loop. The bundled extractor uses
  `u64big()` which returns a BigInt, and converts to Number only after
  masking with `& 0x7FFFFFFFn`.
- **CodeView debug directory entry field offsets.** The
  IMAGE_DEBUG_DIRECTORY structure is 28 bytes with Type at offset 12
  (not 16), SizeOfData at offset 16, AddressOfRawData (RVA) at offset
  20, and PointerToRawData (file offset) at offset 24. Get any of these
  wrong and the extractor reports "no CodeView info" on a file that
  definitely has it.
- **GUID byte order.** CodeView GUIDs are stored as `u32 + u16 + u16 +
  8 bytes`. The first three fields are little-endian (so the GUID
  string is the hex of the LE value); the last 8 bytes are taken
  verbatim. The full 32-char GUID is `g1.toString(16).padStart(8,'0')`
  + `g2.toString(16).padStart(4,'0')` + `g3.toString(16).padStart(4,'0')`
  + `g4Hex`. Getting this wrong makes your symbol-server URL 404.
- **`const` is not `let`.** Anywhere you walk a buffer with
  `const nameOff = ...` and then `nameOff++` inside a loop, JavaScript
  throws "Assignment to constant variable". Use `let` for any variable
  that gets reassigned, even if it conceptually "feels" constant. This
  bug silently broke the exports parser in the first build of this skill.
- **Canvas premultiplication** (inherited from scr-extractor) — never
  validate image bytes through `toDataURL()`; compare raw pixels. The
  bundled exact-PNG encoder writes RGBA verbatim via uncompressed DEFLATE
  stored blocks so downloaded PNGs match the source payload byte-for-byte.
- **CFG entry flag bits** — each `GuardCFFunctionTable` entry is a u32
  RVA with the **low 2 bits** as flags: bit 0 = export-suppressed (the
  symbol exists but cannot be called indirectly), bit 1 = delay-load IAT
  entry. Always mask with `& ~0x3` before treating it as an RVA.
- **Virtualization is mandatory for big export tables.** ntoskrnl.exe
  has 3,298 exports; a typical Windows .sys driver has 100-500. The HTML
  extractor renders 400 rows at a time + a "Load more…" button. Without
  virtualization, dropping ntoskrnl.exe freezes the browser for ~5 s.

## Worked example: ntoskrnl.exe (reference output)

Verified against Win11 10.0.22621.4319 — both the HTML extractor and
`scripts/extract_exe_intel.py` produce identical numbers.

| Metric | Value | Where it lives |
|---|---|---|
| File size | 11,549,808 B (11.0 MB) | — |
| Machine | x86-64 (0x8664) | COFF header |
| Subsystem | NATIVE (kernel, 1) | Optional header |
| Image base | 0x140000000 | Optional header |
| Entry point RVA | 0x604E0 | Optional header |
| Sections | 34 | section table |
| Exports | 3,298 | `.edata` |
| Imported DLLs | 19 | `.idata` |
| Imported functions | 182 | `.idata` |
| PDB filename | ntkrnlmp.pdb | CodeView debug dir |
| PDB GUID | 7D91B8E878B8A42A1B9BFAB4FDC727BD | CodeView debug dir |
| PDB age | 1 | CodeView debug dir |
| Authenticode size | 9,672 B (PKCS#7) | Security dir |
| CFG targets | 8,295 | GFIDS section |
| Exception entries | 38,877 | `.pdata` |
| Resources | 10 leaves (7 BITMAP + 1 RCDATA + 1 MESSAGETABLE + 1 VERSION) | `.rsrc` |
| Section with most flags | `.text` (EXECUTE, READ, CODE) | section table |
| Largest section | `PAGE` (4.0 MB of pageable kernel code) | section table |
| Security cookie VA | 0x140C0CFF0 | Load Config |
| GuardCFFunctionTable VA | 0x140162000 (GFIDS section) | Load Config |

Top 10 export prefixes: `Rt` 529 (runtime), `Io` 360 (I/O manager),
`Ke` 285 (kernel), `Zw` 260 (system services), `Ex` 238 (executive),
`Fs` 229 (filesystem runtime), `Ps` 204 (process/thread), `Mm` 129
(memory manager), `Se` 115 (security), `Nt` 113 (system services).

Extracted Authenticode cert chain:
- `Microsoft Windows` (leaf, validity 2025-06-19 → 2026-06-17, serial 229879+505336)
- ← `Microsoft Windows Production PCA 2011` (intermediate CA)
- ← `Microsoft Root Certificate Authority 2010` (root, trusted by Windows)
- Plus RFC 3161 timestamp countersignature chain: `Microsoft Time-Stamp Service`
  ← `Microsoft Time-Stamp PCA 2010` ← `Microsoft Root Certificate Authority 2010`

## Bundled files — when to read what

| Path | Read/use when |
|---|---|
| `assets/extractor.html` | the user (or you) needs a no-install visual PE introspection tool — copy it out and open it |
| `scripts/extract_exe_intel.py` | headless extraction of any PE file (writes JSON + raw .p7b + resources) |
| `references/pe32-plus.md` | the on-disk PE32+ format in depth (optional header layout, data directory offsets, BigInt gotchas) |
| `references/kernel-sections.md` | the 34 kernel sections of ntoskrnl.exe explained (PAGE / PAGELK / PAGEKD / KVASCODE / RETPOL / GFIDS / CFGRO / INITKDBG) |
| `references/cfg-guard.md` | Control Flow Guard in depth — how the GuardCFFunctionTable is laid out, what the flag bits mean, how the runtime check works |
| `references/authenticode.md` | the PKCS#7 / WIN_CERTIFICATE structure, how the message digest is computed (which parts of the file are hashed), how to verify a signature offline |
| `scr-extractor/references/ico-reconstruction.md` | (inherited) building `.ico` files from RT_GROUP_ICON + RT_ICON leaves — useful if the PE you're inspecting has icons |
| `scr-extractor/references/re-methodology.md` | (inherited) when an export's body needs to actually be disassembled to understand what it does |

## Relationship to mun-extractor and scr-extractor

This skill is the **executable-focused** sibling in the same family:

- **`mun-extractor`** is for `.mun` files (pure-resource PEs, Windows 10 RS5+).
  The lens is "what pictures / icons / assets are inside this file".
- **`scr-extractor`** is for `.scr` screensavers — same resource-tree walker
  as mun-extractor, but specialized for the TGA-textures-hiding-as-"BMP"
  pattern used by Windows screensavers.
- **`exe-extractor`** (this skill) is for `.exe`/`.sys`/`.dll` — same PE
  parser, same resource walker, but the lens shifts to "what API does
  this binary expose, what does it depend on, who signed it, and what
  security mitigations does it have". Resources are still extracted but
  they're a side-show, not the main act.

All three share the same proven `PE` JavaScript class (PE32 + PE32+
support, identical resource tree walker, identical ICO/TGA/DIB decoders
when needed). Use whichever one matches your input.

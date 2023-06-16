# WinDbg Cheat Sheet

## Extension Commands

### Command: `.load`

Use case: Load a specific extension DLL for additional debugging functionality.

Syntax:
.load <dll_name>

Example:
.load myextension.dll

## Analysis and Information Commands

### Command: `!analyze -v`

Use case: Perform an automatic analysis of the current crash dump.

Syntax:
!analyze -v

### Command: `lm`

Use case: List loaded modules and their addresses.

Syntax:
lm

### Command: `!process`

Use case: Display information about processes and their details.

Syntax:
!process

### Command: `!threads`

Use case: List all threads in the current process.

Syntax:
!threads

## Breakpoints and Execution Control Commands

### Command: `bp`

Use case: Set a breakpoint at a specific address or function.

Syntax:
bp <address>

Example:
bp myapp!MyFunction

### Command: `g`

Use case: Continue execution after hitting a breakpoint.

Syntax:
g

### Command: `kv`

Use case: Display a stack trace of the current thread.

Syntax:
kv

## Register and Memory Commands

### Command: `r`

Use case: Display or modify register values.

Syntax:
r

### Command: `dd`

Use case: Display memory content at a specific address.

Syntax:
dd <address>

Example:
dd 0x12345678

### Command: `u`

Use case: Disassemble instructions at a specific address.

Syntax:
u <address>

Example:
u myapp!MyFunction

### Command: `dps`

Use case: Display the stack contents at a specific address.

Syntax:
dps <address>

Example:
dps esp

### Command: `x`

Use case: Examine memory at a specific address with various display formats.

Syntax:
x <address>

Example:
x 0x12345678

## Heap and Memory Management Commands

### Command: `!heap`

Use case: Display heap information and statistics.

Syntax:
!heap

### Command: `!peb`

Use case: Display the Process Environment Block (PEB) for the current process.

Syntax:
!peb

### Command: `!teb`

Use case: Display the Thread Environment Block (TEB) for the current thread.

Syntax:
!teb

## Symbol Management Commands

### Command: `.sympath`

Use case: Set the symbol path for loading symbol files.

Syntax:
.sympath <symbol_path>

Example:
.sympath C:\Symbols

### Command: `lmf`

Use case: List loaded modules and their associated symbols.

Syntax:
lmf

## Additional Advanced Commands

### Command: `sxe`

Use case: Set an exception breakpoint for a specific exception code.

Syntax:
sxe <exception_code>

Example:
sxe c0000005  // Break on Access Violation (AV) exception

### Command: `!exploitable`

Use case: Analyze the exploitability of a crash.

Syntax:
!exploitable

### Command: `uf`

Use case: Unassemble a function at a specific address.

Syntax:
uf <address>

Example:
uf myapp!MyFunction

### Command: `!heap -stat -h <heap_address>`

Use case: Display detailed statistics for a specific heap.

Syntax:
!heap -stat -h <heap_address>

Example:
!heap -stat -h 00120000

These commands cover a wide range of functionalities in WinDbg for debugging and analysis. Refer to the appropriate section based on your debugging needs.

Happy debugging!

## A simple ptrace debugger implemenation
# my-ptrace-debugger

A simple Linux debugger written in C using the `ptrace` system call.  
This project was built to gain hands-on experience with low-level debugging, process tracing, and program execution control on Linux.

It provides a minimal interactive debugger that can attach to a program, control its execution, and inspect internal process state such as registers and breakpoints.

---

## Features

- Trace and control a program using `ptrace`
- Set, list, and delete software breakpoints
- Continue execution and single-step instructions
- Inspect CPU registers
- Modify register values at runtime
- Display the current instruction pointer (RIP)
- List functions found in the target binary
- Basic disassembly by function name
- Interactive command-line interface

---

## Commands

The debugger supports the following commands:

- `break (b)` – Set a breakpoint at a given address  
- `continue (c)` – Resume program execution  
- `step (s)` – Execute a single instruction  
- `registers (reg)` – Display CPU register values  
- `modify reg (m)` – Modify the value of a register  
- `rip (r)` – Show the current instruction pointer  
- `disassemble (d)` – Disassemble a function  
- `list (l)` – List all active breakpoints  
- `delete (del)` – Remove a breakpoint  
- `func (f)` – List functions in the binary  
- `help (h)` – Show available commands  
- `exit (e)` – Exit the debugger  

---

## Usage

Compile the debugger:

```bash
gcc break_points.c command_history.c my_dgb.c parse_elf_info.c  -o my_dbg -lreadline -lcapstone
```
Run with target binary: 
```bash
./my_dbg <program>
```


## TODO

- Add handling for pie executable(only works for non-pie compiled binaries)
- Add MAKEFILE
- Add better error handling

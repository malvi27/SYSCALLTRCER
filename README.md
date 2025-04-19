# SYSCALLTRCER

## Overview
This project demonstrates how to use the `ptrace` system call in Linux to trace and monitor system calls made by a target program. It consists of two components:

1. **`syscall_tracer.c`**: A system call tracer that attaches to a target program, intercepts its system calls, and prints their names.
2. **`test_program.c`**: A simple program that performs basic file operations (create, write, read, close) to test the tracer.

The tracer uses the `ptrace` API to attach to the target process, intercept system calls, and retrieve information about them. It then maps the system call numbers to their corresponding names using an array of system call names.

## Usage Instructions

### Prerequisites
- A Linux environment with GCC installed.
- Basic knowledge of system calls and debugging tools.

### Steps to Run
1. **Compile the Programs**:
   ```bash
   make

2. **Run the Tracer with the Target Program**:
   ```bash
   ./syscall_tracer ./test_program

3. **Clean Up Generated Files**:
   ```bash
   make clean

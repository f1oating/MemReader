# MemReader - Process Memory Manipulation Library

## Overview
MemReader is a C++ class designed for reading and writing process memory on Windows systems. It provides a convenient interface for interacting with other processes' memory, including pattern scanning, memory allocation, and module inspection.

## Features
- **Process Handling**:
  - Open/close processes by name
  - Query process information
  - Get module information

- **Memory Operations**:
  - Read/write memory with automatic protection handling
  - Pointer chain dereferencing
  - Memory allocation/deallocation within target process
  - Signature scanning (pattern matching)

- **Data Conversion**:
  - Supports all fundamental data types (integers, floats, strings)
  - Automatic buffer management

## Usage

### Basic Setup
```cpp
#include "MemReader.h"

// Create instance for target process
MemReader reader(L"target.exe");

// Open process with desired access rights
reader.Open(PROCESS_ALL_ACCESS);
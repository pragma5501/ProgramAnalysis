# Program Analysis Assignment

**Course**: IC637 - Program Analysis
**Instructor**: Minseok Jeon

## Overview

This repository contains a pointer analysis programming assignment that implements a flow-insensitive, context-insensitive pointer analysis for Java programs using Andersen's algorithm. The assignment provides a complete analysis framework built on the Soot static analysis toolkit, with automated fact extraction and a structured pipeline from JAR files to analysis results.

## Quick Start

```bash
# Navigate to the assignment directory
cd Assignment/

# Run analysis on a benchmark program
python3 main.py benchmarks/alloc/Alloc.jar --verbose

# Test all benchmarks
python3 main.py benchmarks/move/Move.jar --verbose
python3 main.py benchmarks/load/Load.jar --verbose
python3 main.py benchmarks/store/Store.jar --verbose
python3 main.py benchmarks/static_call/StaticCall.jar --verbose
python3 main.py benchmarks/special_call/SpecialCall.jar --verbose
python3 main.py benchmarks/virtual_call/VirtualCall.jar --verbose
```

## Repository Structure

```
programAnalysis/
├── Assignment/              # Main assignment directory
│   ├── analysis.py         # 🎯 YOUR IMPLEMENTATION FILE (9 functions to implement)
│   ├── main.py             # Pipeline orchestrator
│   ├── results.py          # Results storage and export
│   ├── bin/                # Soot-based bytecode processing
│   │   ├── JarStmtCollector.java
│   │   └── sootclasses-trunk-jar-with-dependencies.jar
│   ├── frontend/           # Fact extraction pipeline
│   │   ├── extract_facts.py
│   │   └── read_facts.py
│   ├── benchmarks/         # 7 test programs
│   └── results/            # Generated analysis results
├── CLAUDE.md               # Development guidance for Claude Code
└── README.md               # This file
```

## Assignment Objectives

Implement **9 core analysis functions** in `Assignment/analysis.py`:

1. `process_alloc()` - Handle object allocations
2. `process_move()` - Handle variable assignments
3. `process_load()` - Handle field loads
4. `process_store()` - Handle field stores
5. `process_static_call()` - Handle static method calls
6. `process_special_call()` - Handle constructors and super calls
7. `process_virtual_call()` - Handle virtual method dispatch
8. `process_param()` - Handle parameter passing
9. `process_return()` - Handle return values

These functions work together in a fixed-point algorithm to compute three key relations:

- **VarPointsTo**: Which variables point to which objects
- **FldPointsTo**: Which object fields point to which objects
- **CallGraph**: Which methods are called from which invocation sites

## Analysis Pipeline

The framework provides a complete 4-stage pipeline:

1. **Statement Extraction** - Soot processes JAR files into Jimple IR
2. **Fact Extraction** - Jimple statements converted to analysis facts
3. **Pointer Analysis** - Your implementation computes points-to relations
4. **Results Export** - JSON, text reports, and Datalog-style facts generated

## Prerequisites

- **Java 8+** - Required for Soot framework
- **Python 3.6+** - Required for analysis implementation

## Output and Results

Analysis results are generated in `results/analysis_{program}/`:

- `inputs/` - Jimple statement files
- `facts/` - Extracted analysis facts (tab-separated `.facts` files)
- `analysis_results/` - Final output
  - `results.json` - Structured JSON format
  - `detailed_report.txt` - Human-readable report
  - `result_relations/*.facts` - Datalog-style fact files

## Detailed Documentation

For comprehensive implementation guidance, see:

- **`Assignment/README.md`** - Detailed assignment instructions and implementation strategy

## Submission

Submit your completed **`Assignment/analysis.py`** file containing implementations of all 9 required analysis functions.


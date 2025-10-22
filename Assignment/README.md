# Pointer Analysis Programming Assignment

**Course:** IC637 - Program Analysis
**Instructor:** Minseok Jeon
**Assignment:** Implement a flow-insensitive, context-insensitive pointer analysis for Java programs

## Overview

This assignment involves implementing a pointer analysis for Java programs based on **Andersen's algorithm**. The analysis operates on intermediate facts extracted from Java bytecode using the **Soot framework**, and computes three key relations: **variable points-to**, **field points-to**, and **call graph** information.

You will work with a complete automated pipeline that handles bytecode processing, fact extraction, and result generation—allowing you to focus entirely on implementing the core pointer analysis logic.

## Assignment Objectives

Your task is to implement **nine key functions** in the `analysis.py` file within the `PointerAnalysisAnalyzer` class:

1. `process_alloc` - Handle object allocations
2. `process_move` - Handle variable assignments  
3. `process_load` - Handle field loads
4. `process_store` - Handle field stores
5. `process_static_call` - Handle static method calls
6. `process_special_call` - Handle special method calls (constructors, super calls)
7. `process_virtual_call` - Handle virtual method calls
8. `process_param` - Handle parameter passing
9. `process_return` - Handle return values

## What You Need to Know

Your implementation will compute these three relations using a fixed-point algorithm:

- **VarPointsTo(variable, heap)** - Which variables point to which allocation sites
- **FldPointsTo(heap, field, targetHeap)** - Which object fields point to which objects
- **CallGraph(invocationSite, method)** - Which methods are called from which sites

## Repository Structure

```
Assignment/
├── analysis.py              # 🎯 YOUR MAIN IMPLEMENTATION FILE
├── main.py                  # Pipeline orchestrator
├── results.py               # Results storage and export
├── bin/                     # Java bytecode processing tools
│   ├── JarStmtCollector.java    # Soot-based statement extractor
│   └── sootclasses-trunk-jar-with-dependencies.jar
├── frontend/                # Fact extraction pipeline
│   ├── extract_facts.py        # Convert Jimple statements → facts
│   └── read_facts.py           # Data structures and fact reading
├── benchmarks/              # Test programs for validation
│   ├── alloc/Alloc.jar         # Object allocation test
│   ├── move/Move.jar           # Variable assignment test
│   ├── load/Load.jar           # Field load test
│   ├── store/Store.jar         # Field store test
│   ├── static_call/StaticCall.jar    # Static method call test
│   ├── special_call/SpecialCall.jar  # Constructor/super call test
│   └── virtual_call/VirtualCall.jar  # Virtual method call test
└── results/                 # Generated analysis results
```

## Analysis Workflow

The pointer analysis follows this pipeline:

1. **Input**: Java JAR files (use provided benchmarks or your own)
2. **Statement Extraction**: `JarStmtCollector.java` processes JAR → Jimple statements
   - Output: `results/analysis_{program}/inputs/`
3. **Fact Extraction**: `frontend/extract_facts.py` converts statements → analysis facts
   - Output: `results/analysis_{program}/facts/`
4. **Pointer Analysis**: Your `analysis.py` performs the core analysis ⭐
   - Output: `results/analysis_{program}/analysis_results/`

## Quick Start

### Prerequisites

- Java 8+ (for Soot framework)
- Python 3.6+ (for analysis implementation)

### Running Your First Analysis

1. **Test with a simple benchmark:**
   ```bash
   python3 main.py benchmarks/alloc/Alloc.jar --verbose
   ```
2. **Check your results:**
   ```bash
   # Results will be in results/analysis_{program_name}/
   ls results/analysis_Alloc/
   ```

## Program Representation

The analysis works with these facts (stored as tab-separated `.facts` files) in `results/analysis_{program}/facts/` folder:

### Program Facts
- **`HeapAllocation.facts`**: `(variable, allocation_site, method)` - Object allocations
- **`Move.facts`**: `(from_variable, to_variable, method)` - Variable assignments
- **`Load.facts`**: `(to_variable, from_variable, field, method)` - Field loads
- **`Store.facts`**: `(to_variable, field, from_variable, method)` - Field stores
- **`StaticMethodInvocation.facts`**: `(invocation, called_method, enclosing_method)` - Static calls
- **`SpecialMethodInvocation.facts`**: `(invocation, base_variable, called_method, enclosing_method)` - Constructor/super calls
- **`VirtualMethodInvocation.facts`**: `(invocation, base_variable, called_method_name, enclosing_method)` - Virtual calls
- **`HeapAllocation-Type.facts`**: `(allocation_site, allocated_type)` - Allocation types
- **`ActualParam.facts`**: `(index, invocation, variable)` - Call site parameters
- **`FormalParam.facts`**: `(index, method, variable)` - Method parameters
- **`ReturnVar.facts`**: `(variable, method)` - Method return variables
- **`ThisVar.facts`**: `(method, variable)` - This variable bindings
- **`AssignReturnValue.facts`**: `(invocation, variable)` - Return value assignments
- **`Method-Name-Type.facts`**: `(method, method_name, enclosing_class)` - Method metadata
- **`Method.facts`**: `(method)` - Methods in the program


## Understanding the Analysis

Pointer analysis uses **inference rules** to derive points-to facts. You need to implement these nine rules based on Andersen's algorithm. Each rule examines program facts and derives new points-to or call graph relations.

Study the lecture notes and the assignment PDF for the formal specifications of each rule.

## Implementation Strategy

### Key Classes and Methods

In `analysis.py`, the `PointerAnalysisAnalyzer` class provides:

- **Data Access**: `self.data` contains all input facts
- **Result Storage**: `self._var_points_to`, `self._fld_points_to`, `self._call_graph`

### Fixed-Point Algorithm

The main `analysis()` method (already provided) implements a fixed-point iteration that repeatedly applies all nine rules until no new facts are derived.

### Data Structures

In `analysis.py`, the `PointerAnalysisAnalyzer` class provides:

- **Input facts**: `self.data` contains all program facts (allocations, moves, loads, stores, method invocations, etc.)
- **Result storage**:
  - `self._var_points_to` - Set of VarPtsTo facts
  - `self._fld_points_to` - Set of FldPtsTo facts
  - `self._call_graph` - Set of CallGraphEdge facts

Study `frontend/read_facts.py` to understand the available data structures and how to access them.

## Testing Your Implementation

### Benchmark Programs

Each benchmark tests specific aspects:

- **`alloc`**: Basic object allocation (`new A()`, `new B()`)
- **`move`**: Variable assignments (`x = y`)
- **`load`**: Field reads (`x = obj.field`)
- **`store`**: Field writes (`obj.field = x`)
- **`static_call`**: Static method calls (`Class.method()`)
- **`special_call`**: Constructor calls (`new Obj()`)
- **`virtual_call`**: Virtual method calls (`obj.method()`)

### Running Tests

```bash
# Individual tests
python3 main.py benchmarks/alloc/Alloc.jar --verbose
python3 main.py benchmarks/move/Move.jar --verbose
python3 main.py benchmarks/load/Load.jar --verbose
python3 main.py benchmarks/store/Store.jar --verbose
python3 main.py benchmarks/static_call/StaticCall.jar --verbose
python3 main.py benchmarks/special_call/SpecialCall.jar --verbose
python3 main.py benchmarks/virtual_call/VirtualCall.jar --verbose
```

### Validation

After running analysis, check:

1. **Results Directory**: `results/analysis_{program}/analysis_results/`
2. **JSON Output**: `results.json` with structured results
3. **Facts Output**: `.facts` files in Datalog format
4. **Text Report**: `detailed_report.txt` with human-readable analysis

Expected output includes:
- Variable points-to relations showing which variables point to which allocation sites
- Field points-to relations showing object field contents
- Call graph edges showing method call relationships

## Development Tips

### Implementation Approach

Start with simpler rules (like `process_alloc` and `process_move`) before tackling more complex ones (like `process_virtual_call`). Test each function incrementally using the benchmark programs.

### Debugging

- Use `--verbose` flag to see detailed execution logs
- Examine generated `.facts` files in `results/analysis_{program}/facts/` to understand input data
- Check output in `results/analysis_{program}/analysis_results/detailed_report.txt`
- The benchmark source code is available in `benchmarks/*/` directories

### Key Considerations

- The analysis uses a fixed-point iteration, so rules may need multiple iterations to converge
- Result sets automatically handle duplicates
- Virtual call resolution requires understanding object types and method dispatch
- Parameters and return values should only be processed for methods in the call graph

## Submission

Submit your completed **`analysis.py`** file containing implementations of all 9 required analysis functions. Your implementation should correctly compute VarPointsTo, FldPointsTo, and CallGraph relations for the provided benchmark programs.



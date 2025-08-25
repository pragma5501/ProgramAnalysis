# Pointer Analysis Programming Assignment

**Course:** IC637 - Program Analysis  
**Instructor:** Minseok Jeon  
**Assignment:** Implement a flow-insensitive, context-insensitive pointer analysis for Java programs

## Overview

This assignment involves implementing a pointer analysis for Java programs based on Andersen's algorithm. The analysis operates on intermediate facts extracted from Java bytecode using the Soot framework, and computes three key relations: variable points-to, field points-to, and call graph information.

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

## Repository Structure

```
Assignment/
├── analysis.py              # 🎯 YOUR MAIN IMPLEMENTATION FILE
├── main.py                  # Pipeline orchestrator
├── results.py               # Results storage and export
├── requirements.txt         # Python dependencies
├── Dockerfile              # Container setup for consistent environment
├── CLAUDE.md               # Development guidance for Claude Code
├── bin/                    # Java bytecode processing tools
│   ├── JarStmtCollector.java    # Soot-based statement extractor
│   └── sootclasses-trunk-jar-with-dependencies.jar
├── frontend/               # Fact extraction pipeline
│   ├── extract_facts.py        # Convert Jimple statements → facts
│   └── read_facts.py           # Data structures and fact reading
├── benchmarks/             # Test programs for validation
│   ├── alloc/Alloc.jar         # Object allocation test
│   ├── move/Move.jar           # Variable assignment test
│   ├── load/Load.jar           # Field load test
│   ├── store/Store.jar         # Field store test
│   ├── static_call/StaticCall.jar    # Static method call test
│   ├── special_call/SpecialCall.jar  # Constructor/super call test
│   └── virtual_call/VirtualCall.jar  # Virtual method call test
└── results/                # Generated analysis results
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


## Analysis Rules to Implement

Your implementation should compute these three relations:

- **VarPointsTo**: `(variable, allocationSite)` - Which variables point to which objects
- **FldPointsTo**: `(heap, field, mappedHeap)` - Which object fields point to which objects  
- **CallGraph**: `(invocationSite, method)` - Which methods are called from which sites

### The Nine Analysis Rules

1. **Allocation Rule**: Direct variable-to-heap assignments
2. **Move Rule**: Propagate points-to through variable assignments
3. **Load Rule**: Propagate through field reads
4. **Store Rule**: Update field points-to through field writes
5. **Static Call Rule**: Handle static method calls with parameter/return passing
6. **Special Call Rule**: Handle constructors/super calls with this-binding
7. **Virtual Call Rule**: Handle virtual dispatch with type-based method resolution
8. **Param Rule**: Handle parameter passing
9. **Return Rule**: Handle return values

## Implementation Strategy

### Key Classes and Methods

In `analysis.py`, the `PointerAnalysisAnalyzer` class provides:

- **Data Access**: `self.data` contains all input facts
- **Result Storage**: `self._var_points_to`, `self._fld_points_to`, `self._call_graph`

### Fixed-Point Algorithm

The main `analysis()` method implements a fixed-point algorithm:

```python
def analysis(self):
    # Initialize with main method
    main_method = find_main_method(self.data)
    self._call_graph.add(CallGraphEdge(None, main_method))
    
    # Fixed-point iteration
    changed = True
    while changed:
        previous_count = self.results_count()
        
        # Apply all seven rules
        self.process_alloc()
        self.process_move()
        self.process_load()
        self.process_store()
        self.process_static_call()
        self.process_special_call()
        self.process_virtual_call()
        self.process_param()
        self.process_return()
        
        # Check convergence
        changed = (self.results_count() > previous_count)
```

## Testing Your Implementation

### Benchmark Programs

Each benchmark tests specific aspects:

- **`alloc`**: Basic object allocation (`new A()`, `new B()`)
- **`move`**: Variable assignments (`x = y`)
- **`load`**: Field reads (`x = obj.field`)
- **`store`**: Field writes (`obj.field = x`)
- **`static_call`**: Static method calls (`Class.method()`)
- **`special_call`**: Constructor calls (`new Obj()`, `super()`)
- **`virtual_call`**: Virtual method dispatch (`obj.method()`)

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

### Understanding the Data

Study `frontend/read_facts.py` to understand the input data structures:

```python
# Example: Access allocation facts
for alloc in self.data.allocations:
    variable = alloc.variable      # e.g., "<Main: void main()>/r1"  
    heap = alloc.allocation_site   # e.g., "<Main: void main()>/HeapAlloc_1_String"
    method = alloc.method          # e.g., "<Main: void main()>"
```

### Debugging

- Use `--verbose` flag for detailed execution logs
- Examine generated `.facts` files to understand your input
- Check intermediate results during fixed-point iteration
- Print points-to sets at each iteration to see convergence


## Expected Deliverables

Your completed `analysis.py` should:

1. ✅ Implement all seven `process_*` functions correctly
2. ✅ Pass all benchmark tests with correct results
3. ✅ Converge to a fixed point (finite termination)
4. ✅ Generate accurate VarPointsTo, FldPointsTo, and CallGraph relations

## Tips

1. Study the provided benchmark programs and their expected behavior
2. Use the verbose output to trace analysis execution
3. Examine the generated facts files to understand the input format
4. Test incrementally - start with simple benchmarks like `alloc` and `move`


## Submission

Students must submit their completed **`analysis.py`** file containing implementations of the 9 required analysis functions.



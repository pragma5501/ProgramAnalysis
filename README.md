# Program Analysis Assignment

**Course**: IC637 - Program Analysis  
**Instructor**: Minseok Jeon  

## Overview

This repository contains a pointer analysis programming assignment that implements a flow-insensitive, context-insensitive pointer analysis for Java programs using Andersen's algorithm.

## Assignment

The main assignment is located in the `Assignment/` directory, which contains:

- **Complete pointer analysis framework** using the Soot static analysis toolkit
- **9 core analysis functions** to implement in `analysis.py`
- **Benchmark test suite** with 7 different Java programs
- **Automated pipeline** from JAR files to analysis results

## Quick Start

```bash
# Navigate to the assignment directory
cd Assignment/

# See detailed instructions
cat README.md

# Run your first analysis
python3 main.py benchmarks/alloc/Alloc.jar --verbose
```

## Repository Structure

- **`Assignment/`** - Main implementation directory with complete framework
- **`solution.py`**, **`solution2.py`** - Additional solution implementations  
- **`template.py`** - Base template for development

## Learning Objectives

Students will implement a pointer analysis that computes:
- **Variable points-to relations** - Which variables point to which objects
- **Field points-to relations** - Which object fields point to which objects  
- **Call graph** - Method call relationships

## Submission

Students must submit their completed **`Assignment/analysis.py`** file containing implementations of the 9 required analysis functions.


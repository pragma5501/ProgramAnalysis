#!/usr/bin/env python3
"""
Pointer Analysis Data Structures and Fact Reading

This module contains all the data structures and fact reading functionality
extracted from analysis.py to simplify the main analysis code.
"""

import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional


@dataclass(frozen=True)
class HeapAllocationFact:
    """Represents an allocation fact: variable -> heap allocation"""
    variable: str
    allocation_site: str
    method: str


@dataclass(frozen=True)
class HeapAllocTypeFact:
    """Represents allocation type: allocation site -> type"""
    allocation_site: str
    allocated_type: str


@dataclass(frozen=True)
class MoveFact:
    """Represents variable assignment: from_var -> to_var"""
    to_variable: str
    from_variable: str
    method: str


@dataclass(frozen=True)
class LoadFact:
    """Represents field load: to_var = from_var.field"""
    to_variable: str
    from_variable: str
    field: str
    method: str


@dataclass(frozen=True)
class StoreFact:
    """Represents field store: object.field = source_var"""
    to_variable: str
    field: str
    from_variable: str
    method: str


@dataclass(frozen=True)
class ReturnVarFact:
    """Represents return statement: return variable"""
    variable: str
    method: str


@dataclass(frozen=True)
class VirtualInvocationFact:
    """Represents virtual method invocation"""
    invocation: str
    base_variable: str
    called_method_name: str
    enclosing_method: str


@dataclass(frozen=True)
class StaticInvocationFact:
    """Represents static method invocation"""
    invocation: str
    called_method_signature: str
    enclosing_method: str


@dataclass(frozen=True)
class SpecialInvocationFact:
    """Represents special method invocation (constructors, super calls)"""
    invocation: str
    base_variable: str
    called_method_signature: str
    enclosing_method: str


@dataclass(frozen=True)
class ActualParamFact:
    """Represents actual parameter at call site"""
    index: int
    invocation: str
    variable: str


@dataclass(frozen=True)
class FormalParamFact:
    """Represents formal parameter in method signature"""
    index: int
    method: str
    variable: str


@dataclass(frozen=True)
class ThisVarFact:
    """Represents this variable assignment"""
    method: str
    variable: str


@dataclass(frozen=True)
class AssignReturnValueFact:
    """Represents assignment of method invocation return value to variable"""
    invocation: str
    variable: str


@dataclass(frozen=True)
class MethodNameTypeFact:
    """Represents method name and enclosing class triplet"""
    method: str
    method_name: str
    enclosing_class: str




class InputFacts:
    """Container for all pointer analysis facts"""
    
    def __init__(self):
        self.allocations: Set[HeapAllocationFact] = set()
        self.alloc_types: Set[HeapAllocTypeFact] = set()
        self.moves: Set[MoveFact] = set()
        self.loads: Set[LoadFact] = set()
        self.stores: Set[StoreFact] = set()
        self.return_vars: Set[ReturnVarFact] = set()
        self.virtual_invocations: Set[VirtualInvocationFact] = set()
        self.static_invocations: Set[StaticInvocationFact] = set()
        self.special_invocations: Set[SpecialInvocationFact] = set()
        self.actual_params: Set[ActualParamFact] = set()
        self.formal_params: Set[FormalParamFact] = set()
        self.this_vars: Set[ThisVarFact] = set()
        self.assign_return_values: Set[AssignReturnValueFact] = set()
        self.method_name_types: Set[MethodNameTypeFact] = set()
        self.methods: Set[str] = set()


class FactsReader:
    """Reads and parses all .facts files"""
    
    def __init__(self, facts_dir: str = "facts"):
        self.facts_dir = facts_dir
        self.data = InputFacts()
    
    def read_all_facts(self) -> InputFacts:
        """Read all fact files and return populated data structure"""
        if not os.path.exists(self.facts_dir):
            raise FileNotFoundError(f"Facts directory '{self.facts_dir}' not found")
        
        # Read each type of fact file
        self._read_allocations()
        self._read_alloc_types()
        self._read_moves()
        self._read_loads()
        self._read_stores()
        self._read_returns()
        self._read_virtual_invocations()
        self._read_static_invocations()
        self._read_special_invocations()
        self._read_actual_params()
        self._read_formal_params()
        self._read_this_vars()
        self._read_assign_return_values()
        self._read_method_name_types()
        self._read_methods()
        
        return self.data
    
    def _read_fact_file(self, filename: str) -> List[List[str]]:
        """Generic fact file reader that skips comments and headers"""
        filepath = os.path.join(self.facts_dir, filename)
        if not os.path.exists(filepath):
            print(f"Warning: {filename} not found, skipping...")
            return []
        
        facts = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Split by tab
                parts = line.split('\t')
                facts.append(parts)
        
        return facts
    
    def _read_allocations(self):
        """Read HeapAllocation.facts: QualifiedVariable\tQualifiedHeapAllocation\tMethod"""
        facts = self._read_fact_file("HeapAllocation.facts")
        for parts in facts:
            if len(parts) >= 3:
                self.data.allocations.add(HeapAllocationFact(
                    variable=parts[0],
                    allocation_site=parts[1],
                    method=parts[2]
                ))
    
    def _read_alloc_types(self):
        """Read HeapAllocation-Type.facts: AllocationSite\tAllocatedType"""
        facts = self._read_fact_file("HeapAllocation-Type.facts")
        for parts in facts:
            if len(parts) >= 2:
                self.data.alloc_types.add(HeapAllocTypeFact(
                    allocation_site=parts[0],
                    allocated_type=parts[1]
                ))
    
    def _read_moves(self):
        """Read Move.facts: FromVariable\tToVariable\tMethod"""
        facts = self._read_fact_file("Move.facts")
        for parts in facts:
            if len(parts) >= 3:
                self.data.moves.add(MoveFact(
                    from_variable=parts[0],
                    to_variable=parts[1],
                    method=parts[2]
                ))
    
    def _read_loads(self):
        """Read Load.facts: ToVariable\tFromVariable\tField\tMethod"""
        facts = self._read_fact_file("Load.facts")
        for parts in facts:
            if len(parts) >= 4:
                self.data.loads.add(LoadFact(
                    to_variable=parts[0],
                    from_variable=parts[1],
                    field=parts[2],
                    method=parts[3]
                ))
    
    def _read_stores(self):
        """Read Store.facts: ObjectVariable\tField\tSourceVariable\tMethod"""
        facts = self._read_fact_file("Store.facts")
        for parts in facts:
            if len(parts) >= 4:
                self.data.stores.add(StoreFact(
                    to_variable=parts[0],
                    field=parts[1],
                    from_variable=parts[2],
                    method=parts[3]
                ))
    
    def _read_returns(self):
        """Read ReturnVar.facts: Variable\tMethod"""
        facts = self._read_fact_file("ReturnVar.facts")
        for parts in facts:
            if len(parts) >= 2:
                self.data.return_vars.add(ReturnVarFact(
                    variable=parts[0],
                    method=parts[1]
                ))
    
    def _read_virtual_invocations(self):
        """Read VirtualMethodInvocation.facts: Invocation\tBaseVariable\tCalledMethod\tEnclosingMethod"""
        facts = self._read_fact_file("VirtualMethodInvocation.facts")
        for parts in facts:
            if len(parts) >= 4:
                self.data.virtual_invocations.add(VirtualInvocationFact(
                    invocation=parts[0],
                    base_variable=parts[1],
                    called_method_name=parts[2],
                    enclosing_method=parts[3]
                ))
    
    def _read_static_invocations(self):
        """Read StaticMethodInvocation.facts: Invocation\tCalledMethod\tEnclosingMethod"""
        facts = self._read_fact_file("StaticMethodInvocation.facts")
        for parts in facts:
            if len(parts) >= 3:
                self.data.static_invocations.add(StaticInvocationFact(
                    invocation=parts[0],
                    called_method_signature=parts[1],
                    enclosing_method=parts[2]
                ))
    
    def _read_special_invocations(self):
        """Read SpecialMethodInvocation.facts: Invocation\tBaseVariable\tCalledMethod\tEnclosingMethod"""
        facts = self._read_fact_file("SpecialMethodInvocation.facts")
        for parts in facts:
            if len(parts) >= 4:
                self.data.special_invocations.add(SpecialInvocationFact(
                    invocation=parts[0],
                    base_variable=parts[1],
                    called_method_signature=parts[2],
                    enclosing_method=parts[3]
                ))
    
    def _read_actual_params(self):
        """Read ActualParam.facts: Index\tInvocation\tVariable"""
        facts = self._read_fact_file("ActualParam.facts")
        for parts in facts:
            if len(parts) >= 3:
                try:
                    index = int(parts[0])
                    self.data.actual_params.add(ActualParamFact(
                        index=index,
                        invocation=parts[1],
                        variable=parts[2]
                    ))
                except ValueError:
                    continue  # Skip malformed entries
    
    def _read_formal_params(self):
        """Read FormalParam.facts: Index\tMethod\tVariable"""
        facts = self._read_fact_file("FormalParam.facts")
        for parts in facts:
            if len(parts) >= 3:
                try:
                    index = int(parts[0])
                    self.data.formal_params.add(FormalParamFact(
                        index=index,
                        method=parts[1],
                        variable=parts[2]
                    ))
                except ValueError:
                    continue  # Skip malformed entries
    
    def _read_this_vars(self):
        """Read ThisVar.facts: Method\tVariable"""
        facts = self._read_fact_file("ThisVar.facts")
        for parts in facts:
            if len(parts) >= 2:
                self.data.this_vars.add(ThisVarFact(
                    method=parts[0],
                    variable=parts[1]
                ))
    
    def _read_assign_return_values(self):
        """Read AssignReturnValue.facts: Invocation\tReturnVariable"""
        facts = self._read_fact_file("AssignReturnValue.facts")
        for parts in facts:
            if len(parts) >= 2:
                self.data.assign_return_values.add(AssignReturnValueFact(
                    invocation=parts[0],
                    variable=parts[1]
                ))
    
    def _read_method_name_types(self):
        """Read Method-Name-Type.facts: Method\tMethodName\tEnclosingClass"""
        facts = self._read_fact_file("Method-Name-Type.facts")
        for parts in facts:
            if len(parts) >= 3:
                self.data.method_name_types.add(MethodNameTypeFact(
                    method=parts[0],
                    method_name=parts[1],
                    enclosing_class=parts[2]
                ))
    
    def _read_methods(self):
        """Read Method.facts: Method (one per line)"""
        facts = self._read_fact_file("Method.facts")
        for parts in facts:
            if len(parts) >= 1:
                method = parts[0]
                self.data.methods.add(method)
    


def read_facts(facts_dir: str = "facts") -> InputFacts:
    """Convenience function to read all facts from a directory"""
    reader = FactsReader(facts_dir)
    return reader.read_all_facts()


def find_main_method(data: InputFacts) -> Optional[str]:
    """Find the main method in the program"""
    # Look for standard Java main method patterns
    main_patterns = [
        "main(java.lang.String[])",
        "main(java.lang.String)",
        "main()",
        ": void main("
    ]
    
    # Get all methods from various fact types
    all_methods = set()
    
    # From allocations
    for alloc in data.allocations:
        all_methods.add(alloc.method)
    
    # From moves
    for move in data.moves:
        all_methods.add(move.method)
    
    # From invocations
    for inv in data.virtual_invocations:
        all_methods.add(inv.enclosing_method)
        # all_methods.add(inv.called_method)
    
    for inv in data.static_invocations:
        all_methods.add(inv.enclosing_method)
        # all_methods.add(inv.called_method)
    
    for inv in data.special_invocations:
        all_methods.add(inv.enclosing_method)
        # all_methods.add(inv.called_method)
    
    # Find main method
    for method in all_methods:
        for pattern in main_patterns:
            if pattern in method and "main" in method.lower():
                print(f"Found main method: {method}")
                return method
    
    print("Warning: Main method not found, using first available method")
    return list(all_methods)[0] if all_methods else None


if __name__ == "__main__":
    import sys
    facts_dir = sys.argv[1] if len(sys.argv) > 1 else "facts"
    
    print(f"Reading facts from: {facts_dir}")
    try:
        data = read_facts(facts_dir)
        print(f"Successfully read facts:")
        print(f"  Allocations: {len(data.allocations)}")
        print(f"  Allocation types: {len(data.alloc_types)}")
        print(f"  Moves: {len(data.moves)}")
        print(f"  Loads: {len(data.loads)}")
        print(f"  Stores: {len(data.stores)}")
        print(f"  Return vars: {len(data.return_vars)}")
        print(f"  Virtual invocations: {len(data.virtual_invocations)}")
        print(f"  Static invocations: {len(data.static_invocations)}")
        print(f"  Special invocations: {len(data.special_invocations)}")
        print(f"  Actual parameters: {len(data.actual_params)}")
        print(f"  Formal parameters: {len(data.formal_params)}")
        print(f"  This variables: {len(data.this_vars)}")
        print(f"  Assign return values: {len(data.assign_return_values)}")
        print(f"  Method name types: {len(data.method_name_types)}")
        print(f"  Methods: {len(data.methods)}")
        
        if data.assign_return_values:
            print(f"\nAssignReturnValue facts:")
            for fact in list(data.assign_return_values)[:5]:  # Show first 5
                print(f"  {fact.invocation} -> {fact.variable}")
        
        if data.method_name_types:
            print(f"\nMethodNameType facts:")
            for fact in list(data.method_name_types)[:5]:  # Show first 5
                print(f"  {fact.method} -> {fact.method_name} ({fact.enclosing_class})")
        
        if data.methods:
            print(f"\nMethods facts:")
            for method in list(data.methods)[:5]:  # Show first 5
                print(f"  {method}")
        
                
    except Exception as e:
        print(f"Error reading facts: {e}")
        sys.exit(1)

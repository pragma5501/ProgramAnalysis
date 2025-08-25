#!/usr/bin/env python3
"""
Pointer Analysis Analyzer

Simplified analysis module that uses data structures from frontend.read_facts
and statistics functions from util.stat
"""
from typing import Set
from dataclasses import dataclass
from frontend.read_facts import InputFacts, find_main_method
from itertools import product


def result_sum(varPtsTo, fldPtsTo, callGraph):
    return len(varPtsTo) + len(fldPtsTo) + len(callGraph)


@dataclass(frozen=True)
class CallGraphEdge:
    """Represents a call graph edge: invocationSite -> method"""

    invocationSite: str
    method: str


@dataclass(frozen=True)
class VarPtsTo:
    """Represents a variable points-to: variable -> allocation site"""

    variable: str
    allocationSite: str


@dataclass(frozen=True)
class FldPtsTo:
    """Represents a field points-to: (heap, field) -> mapped heap"""

    heap: str
    field: str
    mappedHeap: str


class PointerAnalysisAnalyzer:
    """Provides analysis capabilities for pointer analysis data"""

    def __init__(self, data: InputFacts):
        self.data = data
        self._var_points_to: Set[VarPtsTo] = set()
        self._fld_points_to: Set[FldPtsTo] = set()
        self._call_graph: Set[CallGraphEdge] = set()

    def results_count(self):
        return (
            len(self._var_points_to) + len(self._fld_points_to) + len(self._call_graph)
        )

    def process_alloc(self):
        # allocation = (variable, allocation_site, method)
        # ToDo
        pass

    def process_move(self):
        # move = (to_variable, from_variable, method)
        # ToDo
        pass

    def process_store(self):
        # store = (to_variable, field, from_variable, method)
        # ToDo
        pass

    def process_load(self):
        # load = (to_variable, from_variable, field, method)
        # ToDo
        pass

    def process_static_call(self):
        # static_call = (invocation, called_method_signature, enclosing_method)
        # ToDo
        pass

    def process_special_call(self):
        # special_call = (invocation, called_method_signature, enclosing_method)
        # ToDo
        pass

    def process_virtual_call(self):
        # virtual_call = (invocation, called_method_tmp, enclosing_method)
        # ToDo
        pass

    def process_param(self):
        # ToDo
        pass

    def process_return(self):
        # ToDo
        pass

    def analysis(self):
        """Run the pointer analysis algorithm"""
        main_method = find_main_method(self.data)
        self._call_graph.add(CallGraphEdge(None, main_method))

        iteration = 0
        changed = True

        # print(self.data.alloc_types)
        # raise

        while changed:
            iteration += 1
            previous_results = self.results_count()
            self.process_alloc()
            self.process_move()
            self.process_load()
            self.process_store()
            self.process_static_call()
            self.process_special_call()
            self.process_virtual_call()
            self.process_param()
            self.process_return()
            
            current_results = self.results_count()
            changed = current_results > previous_results

        print(f"Fixed point reached after {iteration} iterations")

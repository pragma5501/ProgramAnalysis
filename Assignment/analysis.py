#!/usr/bin/env python3
"""
Pointer Analysis Analyzer

Simplified analysis module that uses data structures from frontend.read_facts
and statistics functions from util.stat
"""
from dataclasses import dataclass
from itertools import product
from typing import Set

from frontend.read_facts import InputFacts, find_main_method


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
        iter_item = [self.data.allocations, self._call_graph]
        for alloc, cg in product(*iter_item):
            conditions = [
                alloc.method == cg.method,
            ]
            if all(conditions):
                new_vp = VarPtsTo(alloc.variable, alloc.allocation_site)
                self._var_points_to.add(new_vp)

    def process_move(self):
        # move = (to_variable, from_variable, method)
        new_vps = set()
        iter_item = [self.data.moves, self._var_points_to, self._call_graph]
        for move, vp, cg in product(*iter_item):
            conditions = [
                move.from_variable == vp.variable,
                move.method == cg.method,
            ]
            if all(conditions):
                new_vp = VarPtsTo(move.to_variable, vp.allocationSite)
                self._var_points_to.add(new_vp)

    def process_store(self):
        # store = (from_variable, to_variable, field, method)
        iter_item = [self.data.stores, self._var_points_to, self._var_points_to, self._call_graph]
        for store, vp_from, vp_base, cg in product(*iter_item):
            conditions = [
                store.to_variable == vp_base.variable,
                store.from_variable == vp_from.variable,
                store.method == cg.method,
            ]
            if all(conditions):
                new_fp = FldPtsTo(
                    vp_base.allocationSite, store.field, vp_from.allocationSite
                )
                self._fld_points_to.add(new_fp)

    def process_load(self):
        # load = (to_variable, from_variable, field, method)
        iter_item = [self.data.loads, self._var_points_to, self._fld_points_to, self._call_graph]
        for load, vp, fp, cg in product(*iter_item):
            conditions = [
                load.from_variable == vp.variable,
                load.field == fp.field,
                load.method == cg.method,
                vp.allocationSite == fp.heap
            ]
            if all(conditions):
                new_vp = VarPtsTo(load.to_variable, fp.mappedHeap)
                self._var_points_to.add(new_vp)

    def process_static_call(self):
        # static_call = (invocation, called_method_signature, enclosing_method)

        iter_item = [self.data.static_invocations, self._call_graph]
        for static_call, cg in product(*iter_item):
            conditions = [
                static_call.enclosing_method == cg.method,
            ]
            if all(conditions):
                new_cg = CallGraphEdge(
                    static_call.invocation, static_call.called_method_signature
                )
                self._call_graph.add(new_cg)

    def process_special_call(self):
        # special_call = (invocation, called_method_signature, enclosing_method)

        iter_item = [
            self._call_graph,
            self.data.special_invocations,
            self.data.this_vars,
            self._var_points_to,
        ]
        for cg, special_call, this_var, vp in product(*iter_item):
            conditions = [
                special_call.base_variable == vp.variable,
                special_call.called_method_signature == this_var.method,
                special_call.enclosing_method == cg.method,
            ]
            if all(conditions):
                new_cg = CallGraphEdge(
                    special_call.invocation, special_call.called_method_signature
                )
                new_vp = VarPtsTo(this_var.variable, vp.allocationSite)
                self._call_graph.add(new_cg)
                self._var_points_to.add(new_vp)

    def process_virtual_call(self):
        # virtual_call = (invocation, called_method_tmp, enclosing_method)
        iter_item = [
            self.data.virtual_invocations,
            self._call_graph,
            self._var_points_to,
            self.data.alloc_types,
            self.data.method_name_types,
            self.data.this_vars,
        ]
        for virtual_call, cg, vp, alloc_type, method_name_type, this_var in product(
            *iter_item
        ):
            conditions = [
                virtual_call.base_variable == vp.variable,
                virtual_call.called_method_name == method_name_type.method_name,
                virtual_call.enclosing_method == cg.method,
                vp.allocationSite == alloc_type.allocation_site,
                alloc_type.allocated_type == method_name_type.enclosing_class,
                method_name_type.method == this_var.method,
            ]
            if all(conditions):
                new_cg = CallGraphEdge(
                    virtual_call.invocation, method_name_type.method
                )
                new_vp = VarPtsTo(this_var.variable, vp.allocationSite)
                self._call_graph.add(new_cg)
                self._var_points_to.add(new_vp)

    def process_param(self):
        iter_item = [self._call_graph, self.data.actual_params, self.data.formal_params, self._var_points_to]
        for cg, actual_param, formal_param, vp in product(*iter_item):
            conditions = [
                actual_param.index == formal_param.index,
                actual_param.variable == vp.variable,
                actual_param.invocation == cg.invocationSite,
                formal_param.method == cg.method,
            ]
            if all(conditions):
                new_vp = VarPtsTo(formal_param.variable, vp.allocationSite)
                self._var_points_to.add(new_vp)

    def process_return(self):
        iter_item = [self._call_graph, self.data.assign_return_values, self.data.return_vars, self._var_points_to]
        for cg, assign_return_var, return_var, vp in product(*iter_item):
            conditions = [
                cg.invocationSite == assign_return_var.invocation,
                cg.method == return_var.method,
                return_var.variable == vp.variable,
            ]
            if all(conditions):
                new_vp = VarPtsTo(assign_return_var.variable, vp.allocationSite)
                self._var_points_to.add(new_vp)

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

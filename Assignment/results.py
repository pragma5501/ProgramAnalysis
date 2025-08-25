#!/usr/bin/env python3
"""
Results Storage and Printing Module for Pointer Analysis

This module provides classes and functions to store, manage, and print
pointer analysis results in various formats.
"""

import os
import json
from typing import Set, Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime


# Import the analysis result structures directly from analysis.py
from analysis import VarPtsTo, FldPtsTo, CallGraphEdge

# Create aliases for backward compatibility and cleaner naming
VarPointsTo = VarPtsTo
FieldPointsTo = FldPtsTo  
CallGraphEdge = CallGraphEdge


class AnalysisResults:
    """Container for all pointer analysis results"""
    
    def __init__(self, var_points_to=None, field_points_to=None, call_graph=None):
        """Initialize with optional direct analysis results"""
        self.var_points_to: Set[VarPointsTo] = var_points_to if var_points_to is not None else set()
        self.field_points_to: Set[FieldPointsTo] = field_points_to if field_points_to is not None else set()  
        self.call_graph: Set[CallGraphEdge] = call_graph if call_graph is not None else set()
        self.analysis_time: float = 0.0
        self.iterations: int = 0
        self.timestamp: str = datetime.now().isoformat()
    
    def add_var_points_to(self, variable: str, allocation_site: str, method: str = ""):
        """Add a variable points-to relation"""
        self.var_points_to.add(VarPtsTo(variable, allocation_site))
    
    def add_field_points_to(self, base_heap: str, field: str, target_heap: str, method: str = ""):
        """Add a field points-to relation"""
        self.field_points_to.add(FldPtsTo(base_heap, field, target_heap))
    
    def add_call_graph_edge(self, caller: str, callee: str, invocation_site: str = ""):
        """Add a call graph edge"""
        self.call_graph.add(CallGraphEdge(caller, callee))
    
    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics of the analysis results"""
        return {
            "var_points_to": len(self.var_points_to),
            "field_points_to": len(self.field_points_to),
            "call_graph_edges": len(self.call_graph),
            "total_results": len(self.var_points_to) + len(self.field_points_to) + len(self.call_graph),
            "iterations": self.iterations
        }
    
    def get_methods_in_call_graph(self) -> Set[str]:
        """Get all methods referenced in the call graph"""
        methods = set()
        for edge in self.call_graph:
            if edge.invocationSite:
                methods.add(edge.invocationSite)
            methods.add(edge.method)
        return methods
    
    def get_allocated_types(self) -> Dict[str, int]:
        """Get count of allocation sites by type"""
        type_counts = defaultdict(int)
        for var_pts in self.var_points_to:
            # Extract type from allocation site (assumes format: method/HeapAlloc_N_Type)
            if var_pts.allocationSite and "/HeapAlloc_" in var_pts.allocationSite:
                parts = var_pts.allocationSite.split("_")
                if len(parts) >= 3:
                    type_name = "_".join(parts[2:])  # Handle types with underscores
                    type_counts[type_name] += 1
        return dict(type_counts)
    
    def get_variables_by_method(self) -> Dict[str, Set[str]]:
        """Get variables grouped by method"""
        method_vars = defaultdict(set)
        for var_pts in self.var_points_to:
            # Extract method and variable name from qualified variable (method/variable)
            if var_pts.variable and "/" in var_pts.variable:
                method, var_name = var_pts.variable.rsplit("/", 1)
                method_vars[method].add(var_name)
        return dict(method_vars)


class ResultsPrinter:
    """Utility class for printing analysis results in different formats"""
    
    @staticmethod
    def print_summary(results: AnalysisResults):
        """Print a summary of analysis results"""
        stats = results.get_summary_stats()
        
        print("\n" + "="*50)
        print("POINTER ANALYSIS RESULTS SUMMARY")
        print("="*50)
        print(f"Analysis completed at: {results.timestamp}")
        print(f"Analysis time: {results.analysis_time:.3f} seconds")
        print(f"Iterations: {results.iterations}")
        print()
        print(f"Variable Points-To Relations: {stats['var_points_to']}")
        print(f"Field Points-To Relations: {stats['field_points_to']}")
        print(f"Call Graph Edges: {stats['call_graph_edges']}")
        print(f"Total Results: {stats['total_results']}")
        print("="*50)
    
    @staticmethod
    def print_var_points_to(results: AnalysisResults, limit: Optional[int] = None):
        """Print variable points-to relations"""
        print("\n" + "-"*40)
        print("VARIABLE POINTS-TO RELATIONS")
        print("-"*40)
        
        if not results.var_points_to:
            print("No variable points-to relations found.")
            return

        sorted_relations = sorted(results.var_points_to, key=lambda x: ("", x.variable or ""))
        count = 0
        
        for relation in sorted_relations:
            if limit and count >= limit:
                print(f"... and {len(sorted_relations) - limit} more relations")
                break
            
            if relation.variable:
                print(f"{relation.variable} -> {relation.allocationSite}")
            count += 1
    
    @staticmethod
    def print_field_points_to(results: AnalysisResults, limit: Optional[int] = None):
        """Print field points-to relations"""
        print("\n" + "-"*40)
        print("FIELD POINTS-TO RELATIONS")
        print("-"*40)
        
        if not results.field_points_to:
            print("No field points-to relations found.")
            return
        
        sorted_relations = sorted(results.field_points_to, key=lambda x: ("", x.heap, x.field))
        count = 0
        
        for relation in sorted_relations:
            if limit and count >= limit:
                print(f"... and {len(sorted_relations) - limit} more relations")
                break
            
            print(f"({relation.heap}).{relation.field} -> {relation.mappedHeap}")
            count += 1
    
    @staticmethod
    def print_call_graph(results: AnalysisResults, limit: Optional[int] = None):
        """Print call graph edges"""
        print("\n" + "-"*40)
        print("CALL GRAPH")
        print("-"*40)
        
        if not results.call_graph:
            print("No call graph edges found.")
            return
        
        sorted_edges = sorted(results.call_graph, key=lambda x: (x.invocationSite or "", x.method))
        count = 0
        
        for edge in sorted_edges:
            if limit and count >= limit:
                print(f"... and {len(sorted_edges) - limit} more edges")
                break
            
            caller = edge.invocationSite or "<root>"
            print(f"{caller} -> {edge.method}")
            count += 1
    
    @staticmethod
    def print_statistics(results: AnalysisResults):
        """Print detailed statistics"""
        print("\n" + "-"*40)
        print("DETAILED STATISTICS")
        print("-"*40)
        
        # Allocation types
        allocated_types = results.get_allocated_types()
        if allocated_types:
            print("\nAllocation Types:")
            for type_name, count in sorted(allocated_types.items()):
                print(f"  {type_name}: {count}")
        
        # Methods in call graph
        methods = results.get_methods_in_call_graph()
        print(f"\nMethods in Call Graph: {len(methods)}")
        
        # Variables by method
        method_vars = results.get_variables_by_method()
        if method_vars:
            print(f"\nMethods with Variables: {len(method_vars)}")
            for method, vars_set in sorted(method_vars.items()):
                print(f"  {method}: {len(vars_set)} variables")
    
    @staticmethod
    def print_detailed_report(results: AnalysisResults):
        """Print a comprehensive detailed report"""
        ResultsPrinter.print_summary(results)
        ResultsPrinter.print_statistics(results)
        ResultsPrinter.print_var_points_to(results, limit=50)
        ResultsPrinter.print_field_points_to(results, limit=50)
        ResultsPrinter.print_call_graph(results, limit=50)


class ResultsExporter:
    """Utility class for exporting results to different formats"""
    
    @staticmethod
    def export_to_json(results: AnalysisResults, output_file: str):
        """Export results to JSON format"""
        data = {
            "metadata": {
                "timestamp": results.timestamp,
                "analysis_time": results.analysis_time,
                "iterations": results.iterations,
                "summary": results.get_summary_stats()
            },
            "var_points_to": [asdict(rel) for rel in results.var_points_to],
            "field_points_to": [asdict(rel) for rel in results.field_points_to],
            "call_graph": [asdict(edge) for edge in results.call_graph]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"Results exported to JSON: {output_file}")
    
    @staticmethod
    def export_to_facts(results: AnalysisResults, output_dir: str):
        """Export results to .facts files (Datalog format)"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Write VarPointsTo.facts
        with open(os.path.join(output_dir, "VarPointsTo.facts"), 'w') as f:
            f.write("# Variable Points-To Relations\n")
            f.write("# Format: Variable\\tAllocationSite\\tMethod\n")
            f.write(f"# Total relations: {len(results.var_points_to)}\n\n")
            
            for rel in sorted(results.var_points_to, key=lambda x: ("", x.variable or "")):
                if rel.variable:
                    f.write(f"{rel.variable}\t{rel.allocationSite}\t\n")
        
        # Write FieldPointsTo.facts
        with open(os.path.join(output_dir, "FieldPointsTo.facts"), 'w') as f:
            f.write("# Field Points-To Relations\n")
            f.write("# Format: BaseHeap\\tField\\tTargetHeap\\tMethod\n")
            f.write(f"# Total relations: {len(results.field_points_to)}\n\n")
            
            for rel in sorted(results.field_points_to, key=lambda x: ("", x.heap, x.field)):
                f.write(f"{rel.heap}\t{rel.field}\t{rel.mappedHeap}\t\n")
        
        # Write CallGraph.facts
        with open(os.path.join(output_dir, "CallGraph.facts"), 'w') as f:
            f.write("# Call Graph Edges\n")
            f.write("# Format: CallerMethod\\tCalleeMethod\\tInvocationSite\n")
            f.write(f"# Total edges: {len(results.call_graph)}\n\n")
            
            for edge in sorted(results.call_graph, key=lambda x: (x.invocationSite or "", x.method)):
                caller = edge.invocationSite or ""
                f.write(f"{caller}\t{edge.method}\t{edge.invocationSite}\n")
        
        print(f"Results exported to facts files in: {output_dir}")
    
    @staticmethod
    def export_to_text(results: AnalysisResults, output_file: str):
        """Export results to a human-readable text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Redirect print to file
            import sys
            original_stdout = sys.stdout
            sys.stdout = f
            
            try:
                ResultsPrinter.print_detailed_report(results)
            finally:
                sys.stdout = original_stdout
        
        print(f"Results exported to text report: {output_file}")


def main():
    """Example usage of the results module"""
    # Create sample results
    results = AnalysisResults()
    results.add_var_points_to("var1", "HeapAlloc_1_String", "main")
    results.add_var_points_to("var2", "HeapAlloc_2_Object", "main")
    results.add_call_graph_edge("main", "helper", "invoke_1")
    results.analysis_time = 0.123
    results.iterations = 3
    
    # Print results
    ResultsPrinter.print_detailed_report(results)
    
    # Export results
    ResultsExporter.export_to_json(results, "sample_results.json")
    ResultsExporter.export_to_facts(results, "sample_facts")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Main Pipeline for Pointer Analysis

This script orchestrates the complete pointer analysis pipeline:
1. Takes a JAR file as input
2. Compiles JarStmtCollector if needed
3. Runs Soot-based statement extraction
4. Extracts pointer analysis facts
5. Performs analysis and generates reports

Usage:
    python3 main.py input.jar
    python3 main.py input.jar --include-libraries
    python3 main.py input.jar --output-dir custom_output
"""

import argparse
import os
import sys
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Optional
from results import AnalysisResults, ResultsPrinter, ResultsExporter


class PointerAnalysisPipeline:
    """Main pipeline for pointer analysis"""
    
    def __init__(self, jar_file: str, output_dir: Optional[str] = None, 
                 include_libraries: bool = False, verbose: bool = False):
        self.jar_file = Path(jar_file)
        self.include_libraries = include_libraries
        self.verbose = verbose
        
        # Set up directories
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            # Use JAR file name as base for output directory under results/
            jar_name = self.jar_file.stem
            self.output_dir = Path("results") / f"analysis_{jar_name}"
        
        self.results_dir = self.output_dir / "inputs"
        self.facts_dir = self.output_dir / "facts"
        
        # Required files
        self.java_file = Path("bin/JarStmtCollector.java")
        self.class_file = Path("bin/JarStmtCollector.class")
        self.soot_jar = Path("bin/sootclasses-trunk-jar-with-dependencies.jar")
        self.extract_script = Path("frontend/extract_facts.py")
    
    def log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[INFO] {message}")
    
    def run_command(self, command: List[str], description: str) -> bool:
        """Run a command and return success status"""
        self.log(f"Running: {description}")
        self.log(f"Command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            
            if self.verbose and result.stdout:
                print(result.stdout)
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"ERROR: {description} failed")
            print(f"Command: {' '.join(command)}")
            print(f"Exit code: {e.returncode}")
            if e.stdout:
                print(f"Stdout: {e.stdout}")
            if e.stderr:
                print(f"Stderr: {e.stderr}")
            return False
        except FileNotFoundError:
            print(f"ERROR: Command not found: {command[0]}")
            return False
    
    def check_dependencies(self) -> bool:
        """Check that all required files exist"""
        self.log("Checking dependencies...")
        
        missing_files = []
        
        if not self.jar_file.exists():
            missing_files.append(str(self.jar_file))
        
        if not self.java_file.exists():
            missing_files.append(str(self.java_file))
        
        if not self.soot_jar.exists():
            missing_files.append(str(self.soot_jar))
        
        if not self.extract_script.exists():
            missing_files.append(str(self.extract_script))
        
        if missing_files:
            print("ERROR: Missing required files:")
            for file in missing_files:
                print(f"  - {file}")
            return False
        
        self.log("All dependencies found")
        return True
    
    def setup_output_directories(self) -> bool:
        """Create output directories"""
        self.log(f"Setting up output directories in {self.output_dir}")
        
        try:
            # Ensure parent directories are created (including results/ if needed)
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
            self.facts_dir.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            print(f"ERROR: Failed to create output directories: {e}")
            return False
    
    def compile_java_collector(self) -> bool:
        """Compile JarStmtCollector.java if needed"""
        # Check if Java source file exists first
        if not self.java_file.exists():
            print(f"ERROR: Java source file not found: {self.java_file}")
            return False
        
        # Always compile if class file doesn't exist
        if not self.class_file.exists():
            self.log("JarStmtCollector.class not found, compiling...")
        # Check if class file exists and is newer than java file
        elif self.class_file.stat().st_mtime > self.java_file.stat().st_mtime:
            self.log("JarStmtCollector.class is up to date")
            return True
        else:
            self.log("JarStmtCollector.java is newer, recompiling...")
        
        command = [
            "javac",
            "-cp", str(self.soot_jar),
            str(self.java_file)
        ]
        
        success = self.run_command(command, "Java compilation")
        
        if success and self.class_file.exists():
            self.log("JarStmtCollector.class generated successfully")
        elif success:
            print("WARNING: Compilation succeeded but .class file not found")
        
        return success
    
    def run_statement_extraction(self) -> bool:
        """Run JarStmtCollector to extract statements"""
        self.log("Running statement extraction...")
        
        command = [
            "java",
            "-cp", f"bin:{self.soot_jar}",
            "JarStmtCollector"
        ]
        
        if self.include_libraries:
            command.append("--include-libraries")
        
        command.extend([
            str(self.jar_file),
            str(self.results_dir)
        ])
        
        return self.run_command(command, "Statement extraction")
    
    def run_fact_extraction(self) -> bool:
        """Run frontend/extract_facts.py to generate fact files"""
        self.log("Running fact extraction...")
        
        # Change to output directory temporarily for fact extraction
        original_cwd = os.getcwd()
        
        try:
            os.chdir(self.output_dir)
            
            command = [
                "python3",
                str(original_cwd / self.extract_script)
            ]
            
            success = self.run_command(command, "Fact extraction")
            
        finally:
            os.chdir(original_cwd)
        
        return success
    
    def run_analysis(self) -> Optional[AnalysisResults]:
        """Run pointer analysis and return results"""
        self.log("Running pointer analysis...")
        
        try:
            # Import analysis modules directly
            from frontend.read_facts import FactsReader
            from analysis import PointerAnalysisAnalyzer
            
            # Read facts and create analyzer
            self.log(f"Reading facts from {self.facts_dir}")
            reader = FactsReader(str(self.facts_dir))
            data = reader.read_all_facts()
            analyzer = PointerAnalysisAnalyzer(data)
            
            # Record analysis start time
            analysis_start = time.time()
            
            # Run the analysis
            self.log("Performing pointer analysis...")
            analyzer.analysis()
            
            # Create results container directly from analyzer results
            results = AnalysisResults(
                var_points_to=analyzer._var_points_to,
                field_points_to=analyzer._fld_points_to, 
                call_graph=analyzer._call_graph
            )
            
            # Record analysis time
            results.analysis_time = time.time() - analysis_start
            
            # Count iterations (if available from analyzer)
            results.iterations = getattr(analyzer, 'iterations', 0)
            
            return results
            
        except Exception as e:
            print(f"ERROR: Pointer analysis failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def generate_report(self):
        """Generate a summary report"""
        report_file = self.output_dir / "analysis_report.txt"
        
        self.log(f"Generating report: {report_file}")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=== POINTER ANALYSIS REPORT ===\n")
                f.write(f"JAR file: {self.jar_file}\n")
                f.write(f"Include libraries: {self.include_libraries}\n")
                f.write(f"Analysis timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Output directory: {self.output_dir}\n\n")
                
                # List generated files
                f.write("Generated files:\n")
                if self.results_dir.exists():
                    f.write("  Statement files:\n")
                    for file in sorted(self.results_dir.glob("*.txt")):
                        f.write(f"    - {file.name}\n")
                
                if self.facts_dir.exists():
                    f.write("  Fact files:\n")
                    for file in sorted(self.facts_dir.glob("*.facts")):
                        f.write(f"    - {file.name}\n")
                
                # Add analysis summary if facts exist
                if self.facts_dir.exists():
                    try:
                        from frontend.read_facts import FactsReader
                        from analysis import PointerAnalysisAnalyzer
                        
                        reader = FactsReader(str(self.facts_dir))
                        data = reader.read_all_facts()
                        
                        f.write(f"\nAnalysis Summary:\n")
                        f.write(f"  Allocations: {len(data.allocations)}\n")
                        f.write(f"  Move Operations: {len(data.moves)}\n")
                        f.write(f"  Field Loads: {len(data.loads)}\n")
                        f.write(f"  Field Stores: {len(data.stores)}\n")
                        f.write(f"  Method Invocations: {len(data.virtual_invocations) + len(data.static_invocations) + len(data.special_invocations)}\n")
                    except Exception as e:
                        f.write(f"  (Analysis summary unavailable: {e})\n")
                
                f.write(f"\nFor detailed analysis, run:\n")
                f.write(f"python3 analysis.py --facts-dir {self.facts_dir}\n")
            
            print(f"Report generated: {report_file}")
            
        except Exception as e:
            print(f"WARNING: Failed to generate report: {e}")
    
    def run_pipeline(self) -> bool:
        """Run the complete pipeline"""
        print(f"Starting pointer analysis pipeline for {self.jar_file}")
        print(f"Facts directory: {self.facts_dir}")
        print(f"Output directory: {self.output_dir}")
        
        start_time = time.time()
        
        # Step 1: Check dependencies
        if not self.check_dependencies():
            return False
        
        # Step 2: Setup output directories
        if not self.setup_output_directories():
            return False
        
        # Step 3: Compile Java collector
        if not self.compile_java_collector():
            return False
        
        # Step 4: Extract statements
        if not self.run_statement_extraction():
            return False
        
        # Step 5: Extract facts
        if not self.run_fact_extraction():
            return False
        
        # Step 6: Run analysis
        analysis_results = self.run_analysis()
        if analysis_results is None:
            return False
        
        # Step 7: Print analysis results
        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)
        ResultsPrinter.print_summary(analysis_results)
        ResultsPrinter.print_statistics(analysis_results)
        
        # Print detailed results if verbose mode
        if self.verbose:
            ResultsPrinter.print_var_points_to(analysis_results, limit=20)
            ResultsPrinter.print_field_points_to(analysis_results, limit=20)
            ResultsPrinter.print_call_graph(analysis_results, limit=20)
        
        # Step 8: Export results
        results_output_dir = self.output_dir / "analysis_results"
        results_output_dir.mkdir(exist_ok=True)
        
        # Export to JSON
        json_file = results_output_dir / "results.json"
        ResultsExporter.export_to_json(analysis_results, str(json_file))
        
        # Export to facts format
        facts_output_dir = results_output_dir / "result_relations"
        ResultsExporter.export_to_facts(analysis_results, str(facts_output_dir))
        
        # Export to text report
        text_file = results_output_dir / "detailed_report.txt"
        ResultsExporter.export_to_text(analysis_results, str(text_file))
        
        elapsed_time = time.time() - start_time
        print(f"\nPipeline completed successfully in {elapsed_time:.2f} seconds")
        print(f"Results available in: {self.output_dir}")
        print(f"Detailed results exported to: {results_output_dir}")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Complete pointer analysis pipeline for JAR files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py myapp.jar
  python3 main.py myapp.jar --include-libraries
  python3 main.py myapp.jar --output-dir /tmp/analysis --verbose
  python3 main.py jars/luindex.jar --include-libraries --verbose
        """
    )
    
    parser.add_argument(
        "jar_file",
        help="Path to the JAR file to analyze"
    )
    
    parser.add_argument(
        "--output-dir",
        help="Output directory for analysis results (default: analysis_<jarname>)"
    )
    
    parser.add_argument(
        "--include-libraries",
        action="store_true",
        help="Include library classes from rt.jar in analysis"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before analysis"
    )
    
    args = parser.parse_args()
    
    # Validate JAR file
    if not Path(args.jar_file).exists():
        print(f"ERROR: JAR file not found: {args.jar_file}")
        sys.exit(1)
    
    # Clean output directory if requested
    if args.clean and args.output_dir:
        output_path = Path(args.output_dir)
        if output_path.exists():
            print(f"Cleaning output directory: {output_path}")
            shutil.rmtree(output_path)
    
    # Create and run pipeline
    pipeline = PointerAnalysisPipeline(
        jar_file=args.jar_file,
        output_dir=args.output_dir,
        include_libraries=args.include_libraries,
        verbose=args.verbose
    )
    
    success = pipeline.run_pipeline()
    
    if not success:
        print("\nPipeline failed. Check the error messages above.")
        sys.exit(1)
    
    print("\nPipeline completed successfully!")


if __name__ == "__main__":
    main()

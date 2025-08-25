import soot.*;
import soot.jimple.*;
import soot.options.Options;
import java.io.*;
import java.util.*;
import java.util.jar.*;

/**
 * Collects all types of Jimple statements from all classes in a JAR file
 * in a single Soot invocation and saves them to separate text files.
 */
public class JarStmtCollector {
    
    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        
        if (args.length < 1) {
            System.err.println("Usage: java JarStmtCollector [--include-libraries] <jar_file1> [jar_file2] ... [output_dir]");
            System.err.println("Options:");
            System.err.println("  --include-libraries    Include library classes from rt.jar in analysis");
            System.err.println("Examples:");
            System.err.println("  java JarStmtCollector jars/luindex.jar results/");
            System.err.println("  java JarStmtCollector --include-libraries jars/luindex.jar results/");
            System.exit(1);
        }
        
        // Parse command line arguments
        boolean includeLibraries = false;
        List<String> jarFiles = new ArrayList<>();
        String outputDir = null;
        
        for (String arg : args) {
            if (arg.equals("--include-libraries")) {
                includeLibraries = true;
            } else if (arg.endsWith(".jar")) {
                jarFiles.add(arg);
            } else {
                outputDir = arg;
            }
        }
        
        if (jarFiles.isEmpty()) {
            System.err.println("No JAR files specified!");
            System.exit(1);
        }
        
        // Default output directory based on all JAR names
        if (outputDir == null) {
            StringBuilder dirName = new StringBuilder("jimple_analysis");
            for (String jar : jarFiles) {
                dirName.append("_").append(new File(jar).getName().replace(".jar", ""));
            }
            outputDir = dirName.toString();
        }
        
        
        // Get all classes from all JARs
        List<String> allClassNames = new ArrayList<>();
        StringBuilder classpathBuilder = new StringBuilder(System.getProperty("java.class.path"));
        
        for (String jarFile : jarFiles) {
            List<String> classNames = getClassNamesFromJar(jarFile);
            allClassNames.addAll(classNames);
            classpathBuilder.append(":").append(jarFile);
        }
        
        // Conditionally add rt.jar for library class analysis
        if (includeLibraries) {
            String rtJarPath = "jre1.6/lib/rt.jar";
            if (new java.io.File(rtJarPath).exists()) {
                classpathBuilder.append(":").append(rtJarPath);
                // Add ALL library classes from rt.jar for comprehensive analysis
                List<String> rtClassNames = getClassNamesFromJar(rtJarPath);
                allClassNames.addAll(rtClassNames);
            }
        } else {
            // Still add rt.jar to classpath for dependency resolution, but don't analyze its classes
            String rtJarPath = "jre1.6/lib/rt.jar";
            if (new java.io.File(rtJarPath).exists()) {
                classpathBuilder.append(":").append(rtJarPath);
            }
        }
        
        if (allClassNames.isEmpty()) {
            System.err.println("No classes found in any JAR files!");
            System.exit(1);
        }
        
        // Initialize Soot (ONLY ONCE)
        G.reset();
        Options.v().set_prepend_classpath(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_src_prec(Options.src_prec_class);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_output_dir(outputDir + "/jimple");
        Options.v().set_soot_classpath(classpathBuilder.toString());
        
        // Load all classes with multiple strategies
        for (String className : allClassNames) {
            boolean loaded = false;
            
            // Strategy 1: Try as application class
            try {
                SootClass sootClass = Scene.v().loadClassAndSupport(className);
                sootClass.setApplicationClass();
                loaded = true;
            } catch (Exception e1) {
                // Strategy 2: Try as library class
                try {
                    SootClass sootClass = Scene.v().forceResolve(className, SootClass.BODIES);
                    if (sootClass != null) {
                        sootClass.setLibraryClass();
                        loaded = true;
                    }
                } catch (Exception e2) {
                    // Strategy 3: Try with signatures only
                    try {
                        SootClass sootClass = Scene.v().forceResolve(className, SootClass.SIGNATURES);
                        if (sootClass != null) {
                            sootClass.setLibraryClass();
                            loaded = true;
                        }
                    } catch (Exception e3) {
                        // Strategy 4: Try basic resolution
                        try {
                            SootClass sootClass = Scene.v().forceResolve(className, SootClass.HIERARCHY);
                            if (sootClass != null) {
                                sootClass.setLibraryClass();
                                loaded = true;
                            }
                        } catch (Exception e4) {
                            // All strategies failed - will be reported as skipped
                        }
                    }
                }
            }
        }
        
        // Load necessary classes and run packs
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();
        
        // Collections for all statement types across all classes
        List<String> assignStmts = new ArrayList<>();
        List<String> identityStmts = new ArrayList<>();
        List<String> ifStmts = new ArrayList<>();
        List<String> gotoStmts = new ArrayList<>();
        List<String> tableSwitchStmts = new ArrayList<>();
        List<String> lookupSwitchStmts = new ArrayList<>();
        List<String> enterMonitorStmts = new ArrayList<>();
        List<String> exitMonitorStmts = new ArrayList<>();
        List<String> invokeStmts = new ArrayList<>();
        List<String> returnStmts = new ArrayList<>();
        List<String> returnVoidStmts = new ArrayList<>();
        List<String> throwStmts = new ArrayList<>();
        List<String> nopStmts = new ArrayList<>();
        List<String> breakpointStmts = new ArrayList<>();
        
        // Create jimple output directory
        File jimpleDir = new File(outputDir, "jimple");
        if (!jimpleDir.exists()) {
            jimpleDir.mkdirs();
        }
        
        // Statistics
        int processedClasses = 0;
        int skippedClasses = 0;
        List<String> skippedClassNames = new ArrayList<>();
        
        // Process classes based on options
        List<SootClass> allClasses = new ArrayList<>();
        allClasses.addAll(Scene.v().getApplicationClasses());
        if (includeLibraries) {
            allClasses.addAll(Scene.v().getLibraryClasses());
        }
        
        for (SootClass sootClass : allClasses) {
            try {
                String className = sootClass.getName();
                processedClasses++;
                
                
                // Process all methods in the class with multiple body retrieval strategies
                for (SootMethod method : sootClass.getMethods()) {
                    if (!method.hasActiveBody() && method.isConcrete()) {
                        // Strategy 1: Standard body retrieval
                        try {
                            method.retrieveActiveBody();
                        } catch (Exception e1) {
                            // Strategy 2: Force retrieve for any problematic method
                            try {
                                if (method.hasActiveBody()) {
                                    // Body was created in the exception handler
                                } else {
                                    // Try different approach for phantom classes
                                    if (sootClass.isPhantom()) {
                                        continue;
                                    }
                                    method.retrieveActiveBody();
                                }
                            } catch (Exception e2) {
                                // Strategy 3: Skip only if absolutely cannot retrieve
                                continue;
                            }
                        }
                    }
                    
                    if (!method.hasActiveBody()) {
                        continue;
                    }
                    
                    Body body = method.getActiveBody();
                    String methodSignature = method.getSignature();
                    
                    // Process all units in the method
                    for (Unit unit : body.getUnits()) {
                        String entry = String.format("[%s] %s: %s", className, methodSignature, unit.toString());
                        
                        // Classify and collect each statement type
                        if (unit instanceof AssignStmt) {
                            assignStmts.add(entry);
                            
                            // Also check if the assignment contains an invoke expression
                            AssignStmt assignStmt = (AssignStmt) unit;
                            Value rightOp = assignStmt.getRightOp();
                            if (rightOp instanceof InvokeExpr) {
                                InvokeExpr invokeExpr = (InvokeExpr) rightOp;
                                
                                String invokeType;
                                if (invokeExpr instanceof VirtualInvokeExpr) {
                                    invokeType = "VIRTUAL";
                                } else if (invokeExpr instanceof StaticInvokeExpr) {
                                    invokeType = "STATIC";
                                } else if (invokeExpr instanceof SpecialInvokeExpr) {
                                    invokeType = "SPECIAL";
                                } else if (invokeExpr instanceof InterfaceInvokeExpr) {
                                    invokeType = "INTERFACE";
                                } else if (invokeExpr instanceof DynamicInvokeExpr) {
                                    invokeType = "DYNAMIC";
                                } else {
                                    invokeType = "OTHER";
                                }
                                
                                String invokeEntry = String.format("[%s] %s: %s [%s] -> %s", 
                                    className, methodSignature, unit.toString(), invokeType,
                                    invokeExpr.getMethod().getSignature());
                                invokeStmts.add(invokeEntry);
                            }
                            
                        } else if (unit instanceof IdentityStmt) {
                            identityStmts.add(entry);
                            
                        } else if (unit instanceof IfStmt) {
                            IfStmt ifStmt = (IfStmt) unit;
                            String ifEntry = String.format("[%s] %s: %s -> %s", 
                                className, methodSignature, unit.toString(), ifStmt.getTarget().toString());
                            ifStmts.add(ifEntry);
                            
                        } else if (unit instanceof GotoStmt) {
                            GotoStmt gotoStmt = (GotoStmt) unit;
                            String gotoEntry = String.format("[%s] %s: %s -> %s", 
                                className, methodSignature, unit.toString(), gotoStmt.getTarget().toString());
                            gotoStmts.add(gotoEntry);
                            
                        } else if (unit instanceof TableSwitchStmt) {
                            TableSwitchStmt tableSwitchStmt = (TableSwitchStmt) unit;
                            String switchEntry = String.format("[%s] %s: %s (cases: %d-%d, targets: %d, default: %s)", 
                                className, methodSignature, unit.toString(),
                                tableSwitchStmt.getLowIndex(), tableSwitchStmt.getHighIndex(),
                                tableSwitchStmt.getTargets().size(), tableSwitchStmt.getDefaultTarget());
                            tableSwitchStmts.add(switchEntry);
                            
                        } else if (unit instanceof LookupSwitchStmt) {
                            LookupSwitchStmt lookupSwitchStmt = (LookupSwitchStmt) unit;
                            String switchEntry = String.format("[%s] %s: %s (values: %s, targets: %d, default: %s)", 
                                className, methodSignature, unit.toString(),
                                lookupSwitchStmt.getLookupValues().toString(),
                                lookupSwitchStmt.getTargets().size(), lookupSwitchStmt.getDefaultTarget());
                            lookupSwitchStmts.add(switchEntry);
                            
                        } else if (unit instanceof EnterMonitorStmt) {
                            enterMonitorStmts.add(entry);
                            
                        } else if (unit instanceof ExitMonitorStmt) {
                            exitMonitorStmts.add(entry);
                            
                        } else if (unit instanceof InvokeStmt) {
                            InvokeStmt invokeStmt = (InvokeStmt) unit;
                            InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
                            
                            String invokeType;
                            if (invokeExpr instanceof VirtualInvokeExpr) {
                                invokeType = "VIRTUAL";
                            } else if (invokeExpr instanceof StaticInvokeExpr) {
                                invokeType = "STATIC";
                            } else if (invokeExpr instanceof SpecialInvokeExpr) {
                                invokeType = "SPECIAL";
                            } else if (invokeExpr instanceof InterfaceInvokeExpr) {
                                invokeType = "INTERFACE";
                            } else if (invokeExpr instanceof DynamicInvokeExpr) {
                                invokeType = "DYNAMIC";
                            } else {
                                invokeType = "OTHER";
                            }
                            
                            String invokeEntry = String.format("[%s] %s: %s [%s] -> %s", 
                                className, methodSignature, unit.toString(), invokeType,
                                invokeExpr.getMethod().getSignature());
                            invokeStmts.add(invokeEntry);
                            
                        } else if (unit instanceof ReturnStmt) {
                            returnStmts.add(entry);
                            
                        } else if (unit instanceof ReturnVoidStmt) {
                            returnVoidStmts.add(entry);
                            
                        } else if (unit instanceof ThrowStmt) {
                            throwStmts.add(entry);
                            
                        } else if (unit instanceof NopStmt) {
                            nopStmts.add(entry);
                            
                        } else if (unit instanceof BreakpointStmt) {
                            breakpointStmts.add(entry);
                        }
                    }
                }
                
            } catch (Exception e) {
                skippedClassNames.add(sootClass.getName() + " (Error: " + e.getMessage() + ")");
                skippedClasses++;
                continue;
            }
        }
        
        // Write all results to separate files
        String jarFilesStr = String.join(", ", jarFiles);
        writeToFile(outputDir + "/assign_statements.txt", "Assignment Statements", assignStmts, jarFilesStr);
        writeToFile(outputDir + "/identity_statements.txt", "Identity Statements", identityStmts, jarFilesStr);
        writeToFile(outputDir + "/if_statements.txt", "If Statements", ifStmts, jarFilesStr);
        writeToFile(outputDir + "/goto_statements.txt", "Goto Statements", gotoStmts, jarFilesStr);
        writeToFile(outputDir + "/tableswitch_statements.txt", "Table Switch Statements", tableSwitchStmts, jarFilesStr);
        writeToFile(outputDir + "/lookupswitch_statements.txt", "Lookup Switch Statements", lookupSwitchStmts, jarFilesStr);
        writeToFile(outputDir + "/entermonitor_statements.txt", "Enter Monitor Statements", enterMonitorStmts, jarFilesStr);
        writeToFile(outputDir + "/exitmonitor_statements.txt", "Exit Monitor Statements", exitMonitorStmts, jarFilesStr);
        writeToFile(outputDir + "/invoke_statements.txt", "Invoke Statements", invokeStmts, jarFilesStr);
        writeToFile(outputDir + "/return_statements.txt", "Return Statements", returnStmts, jarFilesStr);
        writeToFile(outputDir + "/returnvoid_statements.txt", "Return Void Statements", returnVoidStmts, jarFilesStr);
        writeToFile(outputDir + "/throw_statements.txt", "Throw Statements", throwStmts, jarFilesStr);
        writeToFile(outputDir + "/nop_statements.txt", "Nop Statements", nopStmts, jarFilesStr);
        writeToFile(outputDir + "/breakpoint_statements.txt", "Breakpoint Statements", breakpointStmts, jarFilesStr);
        
        // Write Jimple files using Soot's output mechanism
        try {
            PackManager.v().writeOutput();
            System.out.println("Jimple files written to: " + outputDir + "/jimple/");
        } catch (Exception e) {
            System.err.println("Warning: Could not write Jimple files: " + e.getMessage());
        }
        
        // Summary
        System.out.println("\n=== PROCESSING SUMMARY ===");
        System.out.println("JAR files analyzed: " + jarFiles.size() + " (" + String.join(", ", jarFiles) + ")");
        System.out.println("Include libraries: " + (includeLibraries ? "Yes" : "No"));
        System.out.println("Total classes found: " + allClassNames.size());
        System.out.println("Application classes: " + Scene.v().getApplicationClasses().size());
        if (includeLibraries) {
            System.out.println("Library classes: " + Scene.v().getLibraryClasses().size());
        }
        System.out.println("Classes processed: " + processedClasses);
        System.out.println("Classes skipped: " + skippedClasses);
        System.out.println("\n=== STATEMENT SUMMARY ===");
        System.out.println("AssignStmt: " + assignStmts.size());
        System.out.println("IdentityStmt: " + identityStmts.size());
        System.out.println("IfStmt: " + ifStmts.size());
        System.out.println("GotoStmt: " + gotoStmts.size());
        System.out.println("TableSwitchStmt: " + tableSwitchStmts.size());
        System.out.println("LookupSwitchStmt: " + lookupSwitchStmts.size());
        System.out.println("EnterMonitorStmt: " + enterMonitorStmts.size());
        System.out.println("ExitMonitorStmt: " + exitMonitorStmts.size());
        System.out.println("InvokeStmt: " + invokeStmts.size());
        System.out.println("ReturnStmt: " + returnStmts.size());
        System.out.println("ReturnVoidStmt: " + returnVoidStmts.size());
        System.out.println("ThrowStmt: " + throwStmts.size());
        System.out.println("NopStmt: " + nopStmts.size());
        System.out.println("BreakpointStmt: " + breakpointStmts.size());
        
        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        System.out.println("\nAnalysis completed in: " + formatTime(totalTime));
        System.out.println("All results saved to: " + outputDir);
    }
    
    private static String formatTime(long milliseconds) {
        if (milliseconds < 1000) {
            return milliseconds + " ms";
        } else if (milliseconds < 60000) {
            return String.format("%.2f seconds", milliseconds / 1000.0);
        } else {
            long minutes = milliseconds / 60000;
            long seconds = (milliseconds % 60000) / 1000;
            return String.format("%d minutes %d seconds", minutes, seconds);
        }
    }
    
    private static List<String> getClassNamesFromJar(String jarPath) {
        List<String> classNames = new ArrayList<>();
        
        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                // Only process .class files
                if (name.endsWith(".class")) {
                    // Convert path to class name (e.g., "com/example/Test.class" -> "com.example.Test")
                    String className = name.replace("/", ".").replace(".class", "");
                    // Skip anonymous classes (contain numbers) but include inner classes
                    if (!className.matches(".*\\$\\d+.*")) {
                        classNames.add(className);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading JAR file: " + e.getMessage());
        }
        
        return classNames;
    }
    
    private static void writeToFile(String filename, String title, List<String> statements, String jarFiles) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("=== " + title + " Collection ===");
            writer.println("JAR Files: " + jarFiles);
            writer.println("Total " + title + " found: " + statements.size());
            writer.println("Generated on: " + new Date());
            writer.println();
            
            for (String stmt : statements) {
                writer.println(stmt);
            }
            
        } catch (IOException e) {
            System.err.println("Error writing to file " + filename + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
}

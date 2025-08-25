#!/usr/bin/env python3
"""
Extract facts from Soot's *.txt file.
"""

import re
import sys
import os
from collections import defaultdict


def extract_method_name_from_signature(method_signature):
    """Extract method name from method signature like '<ClassName: ReturnType methodName(params)>'"""
    if method_signature.startswith('<') and method_signature.endswith('>'):
        # Remove angle brackets: <ClassName: ReturnType methodName(params)>
        inner = method_signature[1:-1]
        if ':' in inner:
            # Split on colon: ClassName: ReturnType methodName(params)
            parts = inner.split(':', 1)
            if len(parts) == 2:
                method_part = parts[1].strip()  # ReturnType methodName(params)
                # Split on space to get: [ReturnType, methodName(params)]
                words = method_part.split()
                if len(words) >= 2:
                    method_with_params = words[1]  # methodName(params)
                    # Extract method name before the opening parenthesis
                    if '(' in method_with_params:
                        return method_with_params[:method_with_params.find('(')]
                    else:
                        return method_with_params
    elif ':' in method_signature:
        # Format: ClassName: ReturnType methodName(params)
        parts = method_signature.split(':', 1)
        if len(parts) == 2:
            method_part = parts[1].strip()  # ReturnType methodName(params)
            words = method_part.split()
            if len(words) >= 2:
                method_with_params = words[1]  # methodName(params)
                if '(' in method_with_params:
                    return method_with_params[:method_with_params.find('(')]
                else:
                    return method_with_params
    return None


def is_primitive_type_variable(qualified_variable):
    """
    Check if a qualified variable represents a primitive type.
    Examples of primitive type variables to exclude:
    - <Method>/int, <Method>/boolean, <Method>/char, etc.
    - Variables with primitive type indicators
    """
    if not qualified_variable:
        return False
    
    # Check if the variable ends with primitive type names
    primitive_types = ['/int', '/boolean', '/char', '/byte', '/short', '/long', '/float', '/double']
    for ptype in primitive_types:
        if qualified_variable.endswith(ptype):
            return True
    
    # Check for primitive variable patterns like $i0, $l1, $f2, $d3, $z4, $b5, $s6, $c7
    if '/' in qualified_variable:
        var_part = qualified_variable.split('/')[-1]
        if re.match(r'^\$[ilfdzbs]\d+$', var_part):
            return True
    
    return False


def parse_statement_file(file_path):
    """
    Parse statement files (assign_statements.txt or identity_statements.txt) and group statements by method.
    Returns a dictionary mapping method signatures to lists of statements.
    """
    method_statements = defaultdict(list)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Warning: File {file_path} not found, skipping...")
        return method_statements
    
    # Skip header lines until we find actual statements
    for line in lines:
        line = line.strip()
        if not line or line.startswith('===') or line.startswith('JAR') or line.startswith('Total') or line.startswith('Generated'):
            continue
            
        # Parse statement format: [ClassName] <MethodSignature>: Statement
        match = re.match(r'\[([^\]]+)\]\s+(<.+?>):\s+(.+)', line)
        if match:
            class_name = match.group(1)
            method_signature = match.group(2)
            statement = match.group(3)
            method_statements[method_signature].append({
                'class': class_name,
                'method': method_signature,
                'statement': statement,
                'original_line': line
            })
    
    return method_statements

def parse_all_statements(assign_file, identity_file, return_file, invoke_file):
    """
    Parse assignment, identity, return, and invoke statement files and combine them.
    """
    assign_statements = parse_statement_file(assign_file)
    identity_statements = parse_statement_file(identity_file)
    return_statements = parse_statement_file(return_file)
    invoke_statements = parse_statement_file(invoke_file)
    
    # Combine all dictionaries
    combined_statements = defaultdict(list)
    
    # Add assignment statements
    for method, stmts in assign_statements.items():
        combined_statements[method].extend(stmts)
    
    # Add identity statements
    for method, stmts in identity_statements.items():
        combined_statements[method].extend(stmts)
    
    # Add return statements
    for method, stmts in return_statements.items():
        combined_statements[method].extend(stmts)
    
    # Add invoke statements
    for method, stmts in invoke_statements.items():
        combined_statements[method].extend(stmts)
    
    return combined_statements

def extract_facts(method_statements):
    """
    Extract allocation sites, move statements, load statements, store statements, return statements, method invocations, actual parameters, formal parameters, and this variables from statements.
    Returns allocation facts, allocation types, move facts, load facts, store facts, return facts, invocation facts, actual parameter facts, formal parameter facts, and this variable facts.
    """
    allocation_sites = []
    alloc_types = []
    move_facts = []
    load_facts = []
    store_facts = []
    return_facts = []
    virtual_invocation_facts = []
    static_invocation_facts = []
    special_invocation_facts = []
    actual_param_facts = []
    formal_param_facts = []
    this_var_facts = []
    assign_return_value_facts = []  # New: invocation -> return variable pairs
    methods_set = set()  # New: collect all unique methods
    method_name_type_triplets = []  # New: triplets of (method, method_name, enclosing_class)
    allocation_counter = 0
    invocation_counter = 0
    invocation_mapping = {}  # New: mapping from statement signature to invocation ID
    
    def get_invocation_id(method_sig, statement, invocation_type):
        """Generate consistent invocation ID for the same method call across different fact files"""
        # Create a normalized key from method signature and core statement
        # Remove decorations like [STATIC] -> <...> to get core statement
        core_statement = statement.split('[')[0].strip()  # Remove everything after [TYPE]
        key = f"{method_sig}|{core_statement}"
        
        if key not in invocation_mapping:
            nonlocal invocation_counter
            invocation_counter += 1
            invocation_mapping[key] = f"{invocation_type}_{invocation_counter}"
        
        return invocation_mapping[key]
    
    # Patterns for different types of allocations (excluding all primitive variables: $i*, $l*, $f*, $d*, $z*, $b*, $s*, $c*)
    # Only keep reference variables ($r*) and non-primitive variables
    new_object_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*new\s+([a-zA-Z_][a-zA-Z0-9_.]*)'
    new_array_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*newarray\s*\(([^)]+)\)\[([^\]]+)\]'
    new_multi_array_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*newmultiarray\s*\(([^)]+)\)\s*\[([^\]]+)\]'
    
    # Pattern for variable-to-variable assignments (moves) - excluding all primitive variables
    # Matches: var1 = var2 (but not allocations, method calls, field access, etc.)
    move_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*$'
    
    # Pattern for cast expressions: var1 = (Type) var2
    cast_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\([^)]+\)\s*(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*$'
    
    # Pattern for identity statements: var := @this: Type or var := @parameter0: Type (excluding all primitive variables)
    identity_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*:=\s*(@(?:this|parameter\d+)):\s*(.+)'
    
    # Pattern for field loads: var = obj.<Class: Type fieldName> OR var = <Class: Type fieldName> (static field)
    load_pattern = r'(\$?[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:(\$?[a-zA-Z_][a-zA-Z0-9_]*)\.|)<([^>]+)>\s*$'
    
    # Pattern for field stores: obj.<Class: Type fieldName> = var
    store_pattern = r'(\$?[a-zA-Z_][a-zA-Z0-9_]*)\.<([^>]+)>\s*=\s*(\$?[a-zA-Z_][a-zA-Z0-9_]*)\s*$'
    
    # Pattern for return statements: return var (excluding all primitive variables)
    return_pattern = r'return\s+(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*$'
    
    # Patterns for method invocations - extract method signatures from the end of the statement
    # Use greedy matching to capture complete method signatures including nested angle brackets
    # Virtual invocation: look for [VIRTUAL] -> <method signature>
    virtual_invoke_pattern = r'virtualinvoke\s+(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\.<.*?>\s*\([^)]*\)\s*\[VIRTUAL\]\s*->\s*<(.*)>'
    # Static invocation: look for [STATIC] -> <method signature>  
    static_invoke_pattern = r'staticinvoke\s+<.*?>\s*\([^)]*\)\s*\[STATIC\]\s*->\s*<(.*)>'
    # Special invocation: look for [SPECIAL] -> <method signature>
    special_invoke_pattern = r'specialinvoke\s+(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\.<.*?>\s*\([^)]*\)\s*\[SPECIAL\]\s*->\s*<(.*)>'
    
    # Assignment with invoke patterns: variable = invokeType ...
    assign_virtual_invoke_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*virtualinvoke\s+(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\.<.*?>\s*\([^)]*\)\s*\[VIRTUAL\]\s*->\s*<(.*)>'
    assign_static_invoke_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*staticinvoke\s+<.*?>\s*\([^)]*\)\s*\[STATIC\]\s*->\s*<(.*)>'
    assign_special_invoke_pattern = r'(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*specialinvoke\s+(\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*)\.<.*?>\s*\([^)]*\)\s*\[SPECIAL\]\s*->\s*<(.*)>'
    
    def extract_class_from_method(method_signature):
        """Extract class name from method signature in various formats"""
        if method_signature.startswith('<') and ':' in method_signature:
            # Format: <ClassName: ReturnType methodName(params)>
            class_name = method_signature[1:method_signature.find(':')]
            return class_name.strip()
        elif ':' in method_signature:
            # Format: ClassName: ReturnType methodName(params)
            class_name = method_signature[:method_signature.find(':')]
            return class_name.strip()
        return None

    for method_sig, statements in method_statements.items():
        # Add this method to the methods set
        methods_set.add(method_sig)
        
        # Extract class name and method name, add to method-name-type triplets
        class_name = extract_class_from_method(method_sig)
        method_name = extract_method_name_from_signature(method_sig)
        if class_name and method_name:
            method_name_type_triplets.append((method_sig, method_name, class_name))
        
        for i, stmt_info in enumerate(statements):
            statement = stmt_info['statement']
            
            # Check for object allocation: $r2 = new MMTkHarness
            new_obj_match = re.search(new_object_pattern, statement)
            if new_obj_match:
                variable = new_obj_match.group(1)
                class_type = new_obj_match.group(2)
                # Skip AssertionError allocations
                if class_type == 'java.lang.AssertionError':
                    continue
                    
                allocation_counter += 1
                heap_allocation = f"HeapAlloc_{allocation_counter}_{class_type}"
                
                # Create method-qualified representations
                qualified_variable = f"{method_sig}/{variable}"
                qualified_heap_allocation = f"{method_sig}/{heap_allocation}"
                
                allocation_sites.append({
                    'qualified_variable': qualified_variable,
                    'qualified_heap_allocation': qualified_heap_allocation,
                    'variable': variable,
                    'heap_allocation': heap_allocation,
                    'method': method_sig,
                    'line_number': i + 1,
                    'type': 'object',
                    'class_type': class_type,
                    'original_statement': statement
                })
                
                # Add to AllocType (allocation site -> type)
                alloc_types.append({
                    'allocation_site': qualified_heap_allocation,
                    'allocated_type': class_type,
                    'allocation_type': 'object'
                })
            
            # Check for array allocation: r2 = newarray (int)[10]
            new_array_match = re.search(new_array_pattern, statement)
            if new_array_match:
                variable = new_array_match.group(1)
                array_type = new_array_match.group(2)
                size = new_array_match.group(3)
                allocation_counter += 1
                heap_allocation = f"HeapAlloc_{allocation_counter}_{array_type}_Array"
                
                # Create method-qualified representations
                qualified_variable = f"{method_sig}/{variable}"
                qualified_heap_allocation = f"{method_sig}/{heap_allocation}"
                
                allocation_sites.append({
                    'qualified_variable': qualified_variable,
                    'qualified_heap_allocation': qualified_heap_allocation,
                    'variable': variable,
                    'heap_allocation': heap_allocation,
                    'method': method_sig,
                    'line_number': i + 1,
                    'type': 'array',
                    'array_type': array_type,
                    'size': size,
                    'original_statement': statement
                })
                
                # Add to AllocType (allocation site -> type)
                alloc_types.append({
                    'allocation_site': qualified_heap_allocation,
                    'allocated_type': f"{array_type}[]",
                    'allocation_type': 'array'
                })
            
            # Check for multi-dimensional array allocation
            new_multi_array_match = re.search(new_multi_array_pattern, statement)
            if new_multi_array_match:
                variable = new_multi_array_match.group(1)
                array_type = new_multi_array_match.group(2)
                dimensions = new_multi_array_match.group(3)
                allocation_counter += 1
                heap_allocation = f"HeapAlloc_{allocation_counter}_{array_type}_MultiArray"
                
                # Create method-qualified representations
                qualified_variable = f"{method_sig}/{variable}"
                qualified_heap_allocation = f"{method_sig}/{heap_allocation}"
                
                allocation_sites.append({
                    'qualified_variable': qualified_variable,
                    'qualified_heap_allocation': qualified_heap_allocation,
                    'variable': variable,
                    'heap_allocation': heap_allocation,
                    'method': method_sig,
                    'line_number': i + 1,
                    'type': 'multi_array',
                    'array_type': array_type,
                    'dimensions': dimensions,
                    'original_statement': statement
                })
                
                # Add to AllocType (allocation site -> type)
                alloc_types.append({
                    'allocation_site': qualified_heap_allocation,
                    'allocated_type': f"{array_type}[][]",
                    'allocation_type': 'multi_array'
                })
            
            # Check for identity statements: var := @this: Type or var := @parameter0: Type
            elif ':=' in statement:
                identity_match = re.search(identity_pattern, statement)
                if identity_match:
                    to_var = identity_match.group(1)       # Destination variable
                    from_var = identity_match.group(2)     # Source (@this or @parameter0)
                    var_type = identity_match.group(3)     # Type information
                    
                    # Create method-qualified representations
                    qualified_from_var = f"{method_sig}/{from_var}"
                    qualified_to_var = f"{method_sig}/{to_var}"
                    
                    # Extract formal parameters from @parameter assignments (only reference types)
                    if from_var.startswith('@parameter'):
                        # Extract parameter index from @parameter0, @parameter1, etc.
                        param_index_match = re.search(r'@parameter(\d+)', from_var)
                        if param_index_match:
                            param_index = int(param_index_match.group(1))
                            # Check if the parameter type is a reference type (not primitive)
                            # Only include if the destination variable is a reference variable (indicates reference type)
                            if (re.match(r'\$r\d+$', to_var) or 
                                (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', to_var) and 
                                 to_var not in ['null', 'boolean', 'true', 'false'] and
                                 not to_var.isdigit() and
                                 not re.match(r'["\'].*["\']', to_var))):
                                formal_param_facts.append({
                                    'index': param_index,
                                    'method': method_sig,
                                    'qualified_variable': qualified_from_var,  # Use @parameter* instead of destination variable
                                    'variable': from_var,  # Use @parameter* instead of destination variable
                                    'param_type': var_type,
                                    'original_statement': statement
                                })
                    
                    # Extract this variable from @this assignments
                    elif from_var == '@this':
                        # Check if destination variable is a reference variable (indicates object type)
                        if (re.match(r'\$r\d+$', to_var) or 
                            (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', to_var) and 
                             to_var not in ['null', 'boolean', 'true', 'false'] and
                             not to_var.isdigit() and
                             not re.match(r'["\'].*["\']', to_var))):
                            this_var_facts.append({
                                'method': method_sig,
                                'qualified_variable': f"{method_sig}/@this",  # Use @this
                                'variable': '@this',  # Use @this
                                'this_type': var_type,
                                'original_statement': statement
                            })
                    
                    move_facts.append({
                        'qualified_from_var': qualified_from_var,
                        'qualified_to_var': qualified_to_var,
                        'from_var': from_var,
                        'to_var': to_var,
                        'method': method_sig,
                        'original_statement': statement,
                        'move_type': 'identity'
                    })
            
            # Check for field loads: var = obj.<Class: Type fieldName>
            elif '.<' in statement and '>' in statement and '=' in statement:
                # Check for field stores first: obj.<Class: Type fieldName> = var
                store_match = re.search(store_pattern, statement)
                if store_match:
                    object_var = store_match.group(1)      # Object variable being stored to
                    field_signature = store_match.group(2)  # Field signature: Class: Type fieldName
                    source_var = store_match.group(3)      # Source variable being stored
                    
                    # Create method-qualified representations
                    qualified_object_var = f"{method_sig}/{object_var}"
                    qualified_source_var = f"{method_sig}/{source_var}"
                    # Field signature should be in format <ClassName: Type fieldName>
                    formatted_field = f"<{field_signature}>"
                    
                    store_facts.append({
                        'qualified_object_var': qualified_object_var,
                        'formatted_field': formatted_field,
                        'qualified_source_var': qualified_source_var,
                        'object_var': object_var,
                        'field_signature': field_signature,
                        'source_var': source_var,
                        'method': method_sig,
                        'original_statement': statement
                    })
                else:
                    # Check for field loads: var = obj.<Class: Type fieldName> OR var = <Class: Type fieldName>
                    load_match = re.search(load_pattern, statement)
                    if load_match:
                        to_var = load_match.group(1)      # Destination variable
                        from_var = load_match.group(2)    # Source object variable (may be None for static fields)
                        field_signature = load_match.group(3)  # Field signature: Class: Type fieldName
                        
                        # Handle both instance field access and static field access
                        if from_var:
                            # Instance field: obj.field
                            qualified_from_var = f"{method_sig}/{from_var}"
                        else:
                            # Static field: <Class: Type field>
                            qualified_from_var = f"{method_sig}/<static>"
                            from_var = "<static>"
                        
                        # Create method-qualified representations
                        qualified_to_var = f"{method_sig}/{to_var}"
                        # Field signature should be in format <ClassName: Type fieldName>
                        formatted_field = f"<{field_signature}>"
                        
                        load_facts.append({
                            'qualified_to_var': qualified_to_var,
                            'qualified_from_var': qualified_from_var,
                            'formatted_field': formatted_field,
                            'to_var': to_var,
                            'from_var': from_var,
                            'field_signature': field_signature,
                            'method': method_sig,
                            'original_statement': statement
                        })
            
            # Check for method invocations
            elif 'invoke' in statement:
                # Check for virtual invocation
                virtual_match = re.search(virtual_invoke_pattern, statement)
                if virtual_match:
                    base_var = virtual_match.group(1)  # Base variable
                    called_method = f"<{virtual_match.group(2)}>"  # Called method signature with angle brackets
                    # Extract parameters from the main invocation (before [VIRTUAL])
                    params_match = re.search(r'virtualinvoke\s+[^<]+<[^>]+>\s*\(([^)]*)\)', statement)
                    params_str = params_match.group(1) if params_match else ""
                    
                    # Add called method to methods set
                    methods_set.add(called_method)
                    
                    # Extract class name and method name, add to method-name-type triplets
                    class_name = extract_class_from_method(called_method)
                    method_name = extract_method_name_from_signature(called_method)
                    if class_name and method_name:
                        method_name_type_triplets.append((called_method, method_name, class_name))
                    invocation_id = get_invocation_id(method_sig, statement, "VirtualInvocation")
                    
                    # Create method-qualified representations
                    qualified_base_var = f"{method_sig}/{base_var}"
                    qualified_invocation = f"{method_sig}/{invocation_id}"
                    
                    virtual_invocation_facts.append({
                        'qualified_invocation': qualified_invocation,
                        'qualified_base_var': qualified_base_var,
                        'called_method': called_method,
                        'enclosing_method': method_sig,
                        'invocation_id': invocation_id,
                        'original_statement': statement
                    })
                    
                    # Add base variable fact for virtual invocation
                    
                    # Method name is now included directly in VirtualMethodInvocation.facts
                    
                    # Extract actual parameters (only reference variables)
                    if params_str.strip():  # Only if there are parameters
                        params = [p.strip() for p in params_str.split(',') if p.strip()]
                        for index, param in enumerate(params):
                            # Check if parameter is a reference variable ($r* or non-primitive variable)
                            # Exclude: primitive types, null, constants, and primitive variables
                            if (re.match(r'\$r\d+$', param) or 
                                (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                                 param not in ['null', 'boolean', 'true', 'false'] and
                                 not param.isdigit() and
                                 not re.match(r'["\'].*["\']', param))):
                                qualified_param = f"{method_sig}/{param}"
                                # Additional check to exclude primitive type variables
                                if not is_primitive_type_variable(qualified_param):
                                    actual_param_facts.append({
                                        'index': index,
                                        'qualified_invocation': qualified_invocation,
                                        'qualified_variable': qualified_param,
                                        'invocation_id': invocation_id,
                                        'param': param,
                                        'method': method_sig
                                    })
                
                # Check for static invocation
                elif re.search(static_invoke_pattern, statement):
                    static_match = re.search(static_invoke_pattern, statement)
                    if static_match:
                        called_method = f"<{static_match.group(1)}>"  # Called method signature with angle brackets
                        # Extract parameters from the main invocation (before [STATIC])
                        params_match = re.search(r'staticinvoke\s+<[^>]+>\s*\(([^)]*)\)', statement)
                        params_str = params_match.group(1) if params_match else ""
                        
                        # Add called method to methods set
                        methods_set.add(called_method)
                        
                        # Extract class name and method name, add to method-name-type triplets
                        class_name = extract_class_from_method(called_method)
                        method_name = extract_method_name_from_signature(called_method)
                        if class_name and method_name:
                            method_name_type_triplets.append((called_method, method_name, class_name))
                        invocation_id = get_invocation_id(method_sig, statement, "StaticInvocation")
                        
                        qualified_invocation = f"{method_sig}/{invocation_id}"
                        
                        static_invocation_facts.append({
                            'qualified_invocation': qualified_invocation,
                            'called_method': called_method,
                            'enclosing_method': method_sig,
                            'invocation_id': invocation_id,
                            'original_statement': statement
                        })
                        
                        # Method name is now included directly in StaticMethodInvocation.facts
                        
                        # Extract actual parameters (only reference variables)
                        if params_str.strip():  # Only if there are parameters
                            params = [p.strip() for p in params_str.split(',') if p.strip()]
                            for index, param in enumerate(params):
                                # Check if parameter is a reference variable ($r* or non-primitive variable)
                                # Exclude: primitive types, null, constants, and primitive variables
                                if (re.match(r'\$r\d+$', param) or 
                                    (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                                     param not in ['null', 'boolean', 'true', 'false'] and
                                     not param.isdigit() and
                                     not re.match(r'["\'].*["\']', param))):
                                    qualified_param = f"{method_sig}/{param}"
                                    # Additional check to exclude primitive type variables
                                    if not is_primitive_type_variable(qualified_param):
                                        actual_param_facts.append({
                                            'index': index,
                                            'qualified_invocation': qualified_invocation,
                                            'qualified_variable': qualified_param,
                                            'invocation_id': invocation_id,
                                            'param': param,
                                            'method': method_sig
                                        })
                
                # Check for special invocation
                elif re.search(special_invoke_pattern, statement):
                    special_match = re.search(special_invoke_pattern, statement)
                    if special_match:
                        base_var = special_match.group(1)  # Base variable
                        called_method = f"<{special_match.group(2)}>"  # Called method signature with angle brackets
                        # Extract parameters from the main invocation (before [SPECIAL])
                        # Pattern: specialinvoke $r8.<A: void <init>(java.lang.Object)>($r7) [SPECIAL] -> ...
                        params_match = re.search(r'specialinvoke\s+.*?\(([^)]*)\)\s*\[SPECIAL\]', statement)
                        params_str = params_match.group(1) if params_match else ""
                        
                        # Add called method to methods set
                        methods_set.add(called_method)
                        
                        # Extract class name and method name, add to method-name-type triplets
                        class_name = extract_class_from_method(called_method)
                        method_name = extract_method_name_from_signature(called_method)
                        if class_name and method_name:
                            method_name_type_triplets.append((called_method, method_name, class_name))
                        invocation_id = get_invocation_id(method_sig, statement, "SpecialInvocation")
                        
                        # Create method-qualified representations
                        qualified_base_var = f"{method_sig}/{base_var}"
                        qualified_invocation = f"{method_sig}/{invocation_id}"
                        
                        special_invocation_facts.append({
                            'qualified_invocation': qualified_invocation,
                            'qualified_base_var': qualified_base_var,
                            'called_method': called_method,
                            'enclosing_method': method_sig,
                            'base_var': base_var,
                            'invocation_id': invocation_id,
                            'original_statement': statement
                        })
                        
                        # Add base variable fact for special invocation
                        
                        # Method name is now included directly in SpecialMethodInvocation.facts
                        
                        # Extract actual parameters (only reference variables)
                        if params_str.strip():  # Only if there are parameters
                            params = [p.strip() for p in params_str.split(',') if p.strip()]
                            for index, param in enumerate(params):
                                # Check if parameter is a reference variable ($r* or non-primitive variable)
                                # Exclude: primitive types, null, constants, and primitive variables
                                if (re.match(r'\$r\d+$', param) or 
                                    (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                                     param not in ['null', 'boolean', 'true', 'false'] and
                                     not param.isdigit() and
                                     not re.match(r'["\'].*["\']', param))):
                                    qualified_param = f"{method_sig}/{param}"
                                    # Additional check to exclude primitive type variables
                                    if not is_primitive_type_variable(qualified_param):
                                        actual_param_facts.append({
                                            'index': index,
                                            'qualified_invocation': qualified_invocation,
                                            'qualified_variable': qualified_param,
                                            'invocation_id': invocation_id,
                                            'param': param,
                                            'method': method_sig
                                        })
            
            # Check for return statements: return var
            elif statement.startswith('return '):
                return_match = re.search(return_pattern, statement)
                if return_match:
                    return_var = return_match.group(1)  # Variable being returned
                    
                    # Create method-qualified representation
                    qualified_return_var = f"{method_sig}/{return_var}"
                    
                    return_facts.append({
                        'qualified_return_var': qualified_return_var,
                        'return_var': return_var,
                        'method': method_sig,
                        'original_statement': statement
                    })
            
            # Check for variable-to-variable moves (only if not an allocation, identity, load, or return)
            elif not (new_obj_match or new_array_match or new_multi_array_match):
                move_match = re.search(move_pattern, statement)
                cast_match = re.search(cast_pattern, statement)
                
                if move_match:
                    from_var = move_match.group(2)  # Source variable
                    to_var = move_match.group(1)    # Destination variable
                    
                    # Create method-qualified representations
                    qualified_from_var = f"{method_sig}/{from_var}"
                    qualified_to_var = f"{method_sig}/{to_var}"
                    
                    move_facts.append({
                        'qualified_from_var': qualified_from_var,
                        'qualified_to_var': qualified_to_var,
                        'from_var': from_var,
                        'to_var': to_var,
                        'method': method_sig,
                        'original_statement': statement,
                        'move_type': 'assign'
                    })
                elif cast_match:
                    from_var = cast_match.group(2)  # Source variable (after cast)
                    to_var = cast_match.group(1)    # Destination variable
                    
                    # Create method-qualified representations
                    qualified_from_var = f"{method_sig}/{from_var}"
                    qualified_to_var = f"{method_sig}/{to_var}"
                    
                    move_facts.append({
                        'qualified_from_var': qualified_from_var,
                        'qualified_to_var': qualified_to_var,
                        'from_var': from_var,
                        'to_var': to_var,
                        'method': method_sig,
                        'original_statement': statement,
                        'move_type': 'cast'
                    })
            
            # Check for assignment with invoke expressions: var = invokeType ...
            assign_virtual_match = re.search(assign_virtual_invoke_pattern, statement)
            if assign_virtual_match:
                return_var = assign_virtual_match.group(1)  # Variable receiving return value
                base_var = assign_virtual_match.group(2)    # Base variable for virtual call
                called_method = f"<{assign_virtual_match.group(3)}>"  # Called method signature with angle brackets
                
                # Add called method to methods set
                methods_set.add(called_method)
                
                # Extract class name and method name, add to method-name-type triplets
                class_name = extract_class_from_method(called_method)
                method_name = extract_method_name_from_signature(called_method)
                if class_name and method_name:
                    method_name_type_triplets.append((called_method, method_name, class_name))
                
                # Find the corresponding invocation ID
                invocation_id = get_invocation_id(method_sig, statement, "VirtualInvocation")
                qualified_invocation = f"{method_sig}/{invocation_id}"
                qualified_return_var = f"{method_sig}/{return_var}"
                qualified_base_var = f"{method_sig}/{base_var}"
                
                # Add virtual invocation fact
                virtual_invocation_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'qualified_base_var': qualified_base_var,
                    'called_method': called_method,
                    'enclosing_method': method_sig,
                    'invocation_id': invocation_id,
                    'original_statement': statement
                })
                
                # Add base variable fact for virtual invocation
                
                # Method name is now included directly in VirtualMethodInvocation.facts
                
                # Extract actual parameters (only reference variables)
                params_match = re.search(r'virtualinvoke\s+[^<]+<[^>]+>\s*\(([^)]*)\)', statement)
                params_str = params_match.group(1) if params_match else ""
                if params_str.strip():  # Only if there are parameters
                    params = [p.strip() for p in params_str.split(',') if p.strip()]
                    for index, param in enumerate(params):
                        # Check if parameter is a reference variable ($r* or non-primitive variable)
                        # Exclude: primitive types, null, constants, and primitive variables
                        if (re.match(r'\$r\d+$', param) or 
                            (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                             param not in ['null', 'boolean', 'true', 'false'] and
                             not re.match(r'^\d+$', param) and  # Exclude numeric constants
                             not re.match(r'^[\'""].*[\'""]$', param))):  # Exclude string literals
                            
                            qualified_param = f"{method_sig}/{param}"
                            # Additional check to exclude primitive type variables
                            if not is_primitive_type_variable(qualified_param):
                                actual_param_facts.append({
                                    'qualified_invocation': qualified_invocation,
                                    'index': index,
                                    'qualified_variable': qualified_param,
                                    'invocation_id': invocation_id,
                                    'param': param,
                                    'method': method_sig
                                })
                
                assign_return_value_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'qualified_return_var': qualified_return_var,
                    'invocation_id': invocation_id,
                    'return_var': return_var,
                    'called_method': called_method,
                    'method': method_sig,
                    'invoke_type': 'virtual'
                })
            
            assign_static_match = re.search(assign_static_invoke_pattern, statement)
            if assign_static_match:
                return_var = assign_static_match.group(1)  # Variable receiving return value
                called_method = f"<{assign_static_match.group(2)}>"  # Called method signature with angle brackets
                
                # Add called method to methods set
                methods_set.add(called_method)
                
                # Extract class name and method name, add to method-name-type triplets
                class_name = extract_class_from_method(called_method)
                method_name = extract_method_name_from_signature(called_method)
                if class_name and method_name:
                    method_name_type_triplets.append((called_method, method_name, class_name))
                
                # Find the corresponding invocation ID
                invocation_id = get_invocation_id(method_sig, statement, "StaticInvocation")
                qualified_invocation = f"{method_sig}/{invocation_id}"
                qualified_return_var = f"{method_sig}/{return_var}"
                
                # Add static invocation fact
                static_invocation_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'called_method': called_method,
                    'enclosing_method': method_sig,
                    'invocation_id': invocation_id,
                    'original_statement': statement
                })
                
                # Method name is now included directly in StaticMethodInvocation.facts
                
                # Extract actual parameters (only reference variables)
                params_match = re.search(r'staticinvoke\s+<[^>]+>\s*\(([^)]*)\)', statement)
                params_str = params_match.group(1) if params_match else ""
                if params_str.strip():  # Only if there are parameters
                    params = [p.strip() for p in params_str.split(',') if p.strip()]
                    for index, param in enumerate(params):
                        # Check if parameter is a reference variable ($r* or non-primitive variable)
                        # Exclude: primitive types, null, constants, and primitive variables
                        if (re.match(r'\$r\d+$', param) or 
                            (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                             param not in ['null', 'boolean', 'true', 'false'] and
                             not re.match(r'^\d+$', param) and  # Exclude numeric constants
                             not re.match(r'^[\'""].*[\'""]$', param))):  # Exclude string literals
                            
                            qualified_param = f"{method_sig}/{param}"
                            # Additional check to exclude primitive type variables
                            if not is_primitive_type_variable(qualified_param):
                                actual_param_facts.append({
                                    'qualified_invocation': qualified_invocation,
                                    'index': index,
                                    'qualified_variable': qualified_param,
                                    'invocation_id': invocation_id,
                                    'param': param,
                                    'method': method_sig
                                })
                
                assign_return_value_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'qualified_return_var': qualified_return_var,
                    'invocation_id': invocation_id,
                    'return_var': return_var,
                    'called_method': called_method,
                    'method': method_sig,
                    'invoke_type': 'static'
                })
            
            assign_special_match = re.search(assign_special_invoke_pattern, statement)
            if assign_special_match:
                return_var = assign_special_match.group(1)  # Variable receiving return value
                base_var = assign_special_match.group(2)    # Base variable for special call
                called_method = f"<{assign_special_match.group(3)}>"  # Called method signature with angle brackets
                
                # Add called method to methods set
                methods_set.add(called_method)
                
                # Extract class name and method name, add to method-name-type triplets
                class_name = extract_class_from_method(called_method)
                method_name = extract_method_name_from_signature(called_method)
                if class_name and method_name:
                    method_name_type_triplets.append((called_method, method_name, class_name))
                
                # Find the corresponding invocation ID
                invocation_id = get_invocation_id(method_sig, statement, "SpecialInvocation")
                qualified_invocation = f"{method_sig}/{invocation_id}"
                qualified_return_var = f"{method_sig}/{return_var}"
                qualified_base_var = f"{method_sig}/{base_var}"
                
                # Add special invocation fact
                special_invocation_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'qualified_base_var': qualified_base_var,
                    'called_method': called_method,
                    'enclosing_method': method_sig,
                    'invocation_id': invocation_id,
                    'original_statement': statement
                })
                
                # Add base variable fact for special invocation
                
                # Method name is now included directly in SpecialMethodInvocation.facts
                
                # Extract actual parameters (only reference variables)
                params_match = re.search(r'specialinvoke\s+.*?\(([^)]*)\)', statement)
                params_str = params_match.group(1) if params_match else ""
                if params_str.strip():  # Only if there are parameters
                    params = [p.strip() for p in params_str.split(',') if p.strip()]
                    for index, param in enumerate(params):
                        # Check if parameter is a reference variable ($r* or non-primitive variable)
                        # Exclude: primitive types, null, constants, and primitive variables
                        if (re.match(r'\$r\d+$', param) or 
                            (re.match(r'\$?(?![ilfdzbs]\d|c\d)[a-zA-Z_][a-zA-Z0-9_]*$', param) and 
                             param not in ['null', 'boolean', 'true', 'false'] and
                             not re.match(r'^\d+$', param) and  # Exclude numeric constants
                             not re.match(r'^[\'""].*[\'""]$', param))):  # Exclude string literals
                            
                            qualified_param = f"{method_sig}/{param}"
                            # Additional check to exclude primitive type variables
                            if not is_primitive_type_variable(qualified_param):
                                actual_param_facts.append({
                                    'qualified_invocation': qualified_invocation,
                                    'index': index,
                                    'qualified_variable': qualified_param,
                                    'invocation_id': invocation_id,
                                    'param': param,
                                    'method': method_sig
                                })
                
                assign_return_value_facts.append({
                    'qualified_invocation': qualified_invocation,
                    'qualified_return_var': qualified_return_var,
                    'invocation_id': invocation_id,
                    'return_var': return_var,
                    'called_method': called_method,
                    'method': method_sig,
                    'invoke_type': 'special'
                })
    
    # Convert methods set to sorted list for consistent output
    methods_list = sorted(list(methods_set))
    
    # Sort method name type triplets by method signature for consistent output
    method_name_type_facts = sorted(method_name_type_triplets, key=lambda x: x[0])
    
    return allocation_sites, alloc_types, move_facts, load_facts, store_facts, return_facts, virtual_invocation_facts, static_invocation_facts, special_invocation_facts, actual_param_facts, formal_param_facts, this_var_facts, assign_return_value_facts, methods_list, method_name_type_facts

def write_alloc_facts(allocation_sites, output_file):
    """
    Write allocation sites to HeapAllocation.facts file.
    Only includes allocations from 'new' keyword (excludes newarray and newmultiarray).
    Format: QualifiedVariable\tQualifiedHeapAllocation\tMethod
    """
    try:
        # Filter to only include 'object' allocations (from 'new' keyword)
        object_allocations = [alloc for alloc in allocation_sites if alloc['type'] == 'object']
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Allocation Facts (new keyword only)\n")
            f.write("# Format: QualifiedVariable\\tQualifiedHeapAllocation\\tMethod\n")
            f.write(f"# Total allocations: {len(object_allocations)}\n\n")
            
            for alloc in object_allocations:
                f.write(f"{alloc['qualified_variable']}\t{alloc['qualified_heap_allocation']}\t{alloc['method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_alloc_type_facts(alloc_types, output_file):
    """
    Write allocation type facts to AllocType.facts file.
    Only includes types for allocations from 'new' keyword (excludes newarray and newmultiarray).
    Format: AllocationSite\tAllocatedType
    """
    try:
        # Filter to only include 'object' allocation types (from 'new' keyword)
        object_alloc_types = [alloc_type for alloc_type in alloc_types if alloc_type['allocation_type'] == 'object']
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Allocation Type Facts (new keyword only)\n")
            f.write("# Format: AllocationSite\\tAllocatedType\n")
            f.write(f"# Total allocation types: {len(object_alloc_types)}\n\n")
            
            for alloc_type in object_alloc_types:
                f.write(f"{alloc_type['allocation_site']}\t{alloc_type['allocated_type']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_move_facts(move_facts, output_file):
    """
    Write move facts to Move.facts file.
    Format: FromVariable\tToVariable\tMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Move Facts\n")
            f.write("# Format: FromVariable\\tToVariable\\tMethod\n")
            f.write(f"# Total moves: {len(move_facts)}\n\n")
            
            for move in move_facts:
                f.write(f"{move['qualified_from_var']}\t{move['qualified_to_var']}\t{move['method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_load_facts(load_facts, output_file):
    """
    Write load facts to Load.facts file.
    Format: ToVariable\tFromVariable\tField\tMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Load Facts\n")
            f.write("# Format: ToVariable\\tFromVariable\\tField\\tMethod\n")
            f.write(f"# Total loads: {len(load_facts)}\n\n")
            
            for load in load_facts:
                f.write(f"{load['qualified_to_var']}\t{load['qualified_from_var']}\t{load['formatted_field']}\t{load['method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_store_facts(store_facts, output_file):
    """
    Write store facts to Store.facts file.
    Format: ObjectVariable\tField\tSourceVariable\tMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Store Facts\n")
            f.write("# Format: ObjectVariable\\tField\\tSourceVariable\\tMethod\n")
            f.write(f"# Total stores: {len(store_facts)}\n\n")
            
            for store in store_facts:
                f.write(f"{store['qualified_object_var']}\t{store['formatted_field']}\t{store['qualified_source_var']}\t{store['method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_return_facts(return_facts, output_file):
    """
    Write return facts to ReturnVar.facts file.
    Format: Variable\tMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Return Variable Facts\n")
            f.write("# Format: Variable\\tMethod\n")
            f.write(f"# Total returns: {len(return_facts)}\n\n")
            
            for ret in return_facts:
                f.write(f"{ret['qualified_return_var']}\t{ret['method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_virtual_invocation_facts(virtual_facts, output_file):
    """
    Write virtual method invocation facts to VirtualMethodInvocation.facts file.
    Format: Invocation\tBaseVariable\tCalledMethod\tEnclosingMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Virtual Method Invocation Facts\n")
            f.write("# Format: Invocation\\tBaseVariable\\tCalledMethod\\tEnclosingMethod\n")
            f.write(f"# Total virtual invocations: {len(virtual_facts)}\n\n")
            
            for invocation in virtual_facts:
                method_name = extract_method_name_from_signature(invocation['called_method'])
                f.write(f"{invocation['qualified_invocation']}\t{invocation['qualified_base_var']}\t{method_name}\t{invocation['enclosing_method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_static_invocation_facts(static_facts, output_file):
    """
    Write static method invocation facts to StaticMethodInvocation.facts file.
    Format: Invocation\tCalledMethod\tEnclosingMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Static Method Invocation Facts\n")
            f.write("# Format: Invocation\\tCalledMethod\\tEnclosingMethod\n")
            f.write(f"# Total static invocations: {len(static_facts)}\n\n")
            
            for invocation in static_facts:
                f.write(f"{invocation['qualified_invocation']}\t{invocation['called_method']}\t{invocation['enclosing_method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_special_invocation_facts(special_facts, output_file):
    """
    Write special method invocation facts to SpecialMethodInvocation.facts file.
    Format: Invocation\tBaseVariable\tCalledMethod\tEnclosingMethod
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Special Method Invocation Facts\n")
            f.write("# Format: Invocation\\tBaseVariable\\tCalledMethod\\tEnclosingMethod\n")
            f.write(f"# Total special invocations: {len(special_facts)}\n\n")
            
            for invocation in special_facts:
                f.write(f"{invocation['qualified_invocation']}\t{invocation['qualified_base_var']}\t{invocation['called_method']}\t{invocation['enclosing_method']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_actual_param_facts(param_facts, output_file):
    """
    Write actual parameter facts to ActualParam.facts file.
    Format: Index\tInvocation\tVariable
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Actual Parameter Facts\n")
            f.write("# Format: Index\\tInvocation\\tVariable\n")
            f.write(f"# Total actual parameters: {len(param_facts)}\n\n")
            
            for param in param_facts:
                f.write(f"{param['index']}\t{param['qualified_invocation']}\t{param['qualified_variable']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_formal_param_facts(formal_facts, output_file):
    """
    Write formal parameter facts to FormalParam.facts file.
    Format: Index\tMethod\tVariable
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Formal Parameter Facts\n")
            f.write("# Format: Index\\tMethod\\tVariable\n")
            f.write(f"# Total formal parameters: {len(formal_facts)}\n\n")
            
            for param in formal_facts:
                f.write(f"{param['index']}\t{param['method']}\t{param['qualified_variable']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_this_var_facts(this_facts, output_file):
    """
    Write this variable facts to ThisVar.facts file.
    Format: Method\tVariable
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# This Variable Facts\n")
            f.write("# Format: Method\\tVariable\n")
            f.write(f"# Total this variables: {len(this_facts)}\n\n")
            
            for this_var in this_facts:
                f.write(f"{this_var['method']}\t{this_var['qualified_variable']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)


def write_methods_facts(methods_list, output_file):
    """
    Write all methods facts to Method.facts file.
    Format: Method (one per line)
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Method Facts\n")
            f.write("# Format: Method\n")
            f.write(f"# Total methods: {len(methods_list)}\n\n")
            
            for method in methods_list:
                f.write(f"{method}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)

def write_method_name_type_facts(method_name_type_facts, output_file):
    """
    Write method-name-type facts to Method-Name-Type.facts file.
    Format: Method\tMethodName\tEnclosingClass
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Method-Name-Type Facts\n")
            f.write("# Format: Method\\tMethodName\\tEnclosingClass\n")
            f.write(f"# Total method-name-class triplets: {len(method_name_type_facts)}\n\n")
            
            for method_sig, method_name, class_name in method_name_type_facts:
                f.write(f"{method_sig}\t{method_name}\t{class_name}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)




def write_assign_return_value_facts(assign_return_value_facts, output_file):
    """
    Write assign return value facts to AssignReturnValue.facts file.
    Format: Invocation\tReturnVariable
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("# Assign Return Value Facts\n")
            f.write("# Format: Invocation\\tReturnVariable\n")
            f.write(f"# Total assign return value pairs: {len(assign_return_value_facts)}\n\n")
            
            for fact in assign_return_value_facts:
                f.write(f"{fact['qualified_invocation']}\t{fact['qualified_return_var']}\n")
    
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")
        sys.exit(1)


def print_statistics(method_statements, allocation_sites, alloc_types, move_facts, load_facts, store_facts, return_facts, virtual_facts, static_facts, special_facts, param_facts, formal_facts, this_facts, assign_return_value_facts, methods_list, method_name_type_facts):
    """Print analysis statistics."""
    print(f"\n=== ANALYSIS SUMMARY ===")
    print(f"Methods analyzed: {len(method_statements)}")
    print(f"Total statements: {sum(len(stmts) for stmts in method_statements.values())}")
    print(f"Allocation sites found: {len(allocation_sites)}")
    print(f"Allocation types found: {len(alloc_types)}")
    print(f"Move statements found: {len(move_facts)}")
    print(f"Load statements found: {len(load_facts)}")
    print(f"Store statements found: {len(store_facts)}")
    print(f"Return statements found: {len(return_facts)}")
    print(f"Virtual invocations found: {len(virtual_facts)}")
    print(f"Static invocations found: {len(static_facts)}")
    print(f"Special invocations found: {len(special_facts)}")
    print(f"Actual parameters found: {len(param_facts)}")
    print(f"Formal parameters found: {len(formal_facts)}")
    print(f"This variables found: {len(this_facts)}")
    print(f"Assign return value pairs found: {len(assign_return_value_facts)}")
    print(f"Total unique methods found: {len(methods_list)}")
    print(f"Method-name-class triplets found: {len(method_name_type_facts)}")
    
    # Count by allocation type
    type_counts = defaultdict(int)
    for alloc in allocation_sites:
        type_counts[alloc['type']] += 1
    
    print(f"\nAllocation types:")
    for alloc_type, count in type_counts.items():
        print(f"  {alloc_type}: {count}")


def main():
    """Main execution function for fact extraction."""
    import sys
    
    # Default output directory and program prefix
    output_dir = "facts"
    program_prefix = ""
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        program_prefix = sys.argv[1]
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Input files (default paths)
    assign_file = "inputs/assign_statements.txt"
    identity_file = "inputs/identity_statements.txt"
    return_file = "inputs/return_statements.txt"
    invoke_file = "inputs/invoke_statements.txt"
    
    print(f"Starting fact extraction...")
    print(f"Program prefix: {program_prefix if program_prefix else '(none)'}")
    print(f"Output directory: {output_dir}")
    
    # Parse all statement files
    method_statements = parse_all_statements(assign_file, identity_file, return_file, invoke_file)
    
    if not method_statements:
        print("No statements found! Make sure the statement files exist in the inputs/ directory.")
        return
    
    # Extract facts
    allocation_sites, alloc_types, move_facts, load_facts, store_facts, return_facts, \
    virtual_facts, static_facts, special_facts, param_facts, formal_facts, this_facts, \
    assign_return_value_facts, methods_list, method_name_type_facts = \
        extract_facts(method_statements)
    
    # Write fact files
    prefix = f"{program_prefix}_" if program_prefix else ""
    write_alloc_facts(allocation_sites, f"{output_dir}/{prefix}HeapAllocation.facts")
    write_alloc_type_facts(alloc_types, f"{output_dir}/{prefix}HeapAllocation-Type.facts")
    write_move_facts(move_facts, f"{output_dir}/{prefix}Move.facts")
    write_load_facts(load_facts, f"{output_dir}/{prefix}Load.facts")
    write_store_facts(store_facts, f"{output_dir}/{prefix}Store.facts")
    write_return_facts(return_facts, f"{output_dir}/{prefix}ReturnVar.facts")
    write_virtual_invocation_facts(virtual_facts, f"{output_dir}/{prefix}VirtualMethodInvocation.facts")
    write_static_invocation_facts(static_facts, f"{output_dir}/{prefix}StaticMethodInvocation.facts")
    write_special_invocation_facts(special_facts, f"{output_dir}/{prefix}SpecialMethodInvocation.facts")
    write_actual_param_facts(param_facts, f"{output_dir}/{prefix}ActualParam.facts")
    write_formal_param_facts(formal_facts, f"{output_dir}/{prefix}FormalParam.facts")
    write_this_var_facts(this_facts, f"{output_dir}/{prefix}ThisVar.facts")
    write_assign_return_value_facts(assign_return_value_facts, f"{output_dir}/{prefix}AssignReturnValue.facts")
    write_methods_facts(methods_list, f"{output_dir}/{prefix}Method.facts")
    write_method_name_type_facts(method_name_type_facts, f"{output_dir}/{prefix}Method-Name-Type.facts")
    
    # Print statistics
    print_statistics(method_statements, allocation_sites, alloc_types, move_facts, 
                    load_facts, store_facts, return_facts, virtual_facts, 
                    static_facts, special_facts, param_facts, formal_facts, this_facts,
                    assign_return_value_facts, methods_list, method_name_type_facts)
    
    print(f"\nFact extraction completed successfully!")
    print(f"All fact files written to: {output_dir}/")


if __name__ == "__main__":
    main()

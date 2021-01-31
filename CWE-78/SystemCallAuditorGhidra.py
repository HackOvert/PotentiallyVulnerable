#Checks system calls for command injection patterns
#@author 
#@category HackOvert
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor

sources = [
    'snprintf', # int snprintf ( char * s, size_t n, const char * format, ... );
    'sprintf',  # int sprintf  ( char * s, const char * format, ... );
]

sinks = [
    'system',   # int system(const char *command);
]

def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()


def get_stack_var_from_varnode(func, varnode):
    if type(varnode) not in [Varnode, VarnodeAST]:
        raise Exception("Invalid value passed to get_stack_var_from_varnode(). Expected `Varnode` or `VarnodeAST`, got {}.".format(type(varnode)))
    
    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset()
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset()
                if unsigned_lv_offset == defop_input_offset:
                    return lv
        
        # If we get here, varnode is likely a "acStack##" variable.
        hf = get_high_function(func)
        lsm = hf.getLocalSymbolMap()

        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset()
            for symbol in lsm.getSymbols():
                if symbol.isParameter(): 
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset():
                    return symbol

    # unable to resolve stack variable for given varnode
    return None


def main():
    fm = currentProgram.getFunctionManager()
    functions = [func for func in fm.getFunctions(True)]

    # ====================================================================
    # Step 1. Check if our target has at least one source and one sink we care about
    function_names = [func.name for func in functions]
    if (set(sources) & set(function_names)) and (set(sinks) & set(function_names)):
        print("This target contains interesting source(s) and sink(s). Continuing analysis...")
    else:
        print("This target does not contain interesting source(s) and sink(s). Done.")
        return


    # ====================================================================
    # Step 2. Find functions that calls at least one source and one sink
    interesting_functions = []
    for func in functions:
        monitor = ConsoleTaskMonitor()
        called_functions = func.getCalledFunctions(monitor)
        called_function_names = [cf.name for cf in called_functions]

        source_callers = set(called_function_names) & set(sources)
        sink_callers = set(called_function_names) & set(sinks)

        if source_callers and sink_callers:
            interesting_functions.append(func)
    
    # Show any interesting functions found
    if len(interesting_functions) <= 0:
        print("\nNo interesting functions found to analyze. Done.")
        return
    else:
        print("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))
        for func in interesting_functions:
            print("  {}".format(func.name))
    

    # ====================================================================
    # Step 3. Dig into interesting functions
    for func in interesting_functions:
        print("\nAnalyzing function: {}".format(func.name))
        
        source_args = []
        sink_args = []

        hf = get_high_function(func)
        opiter = hf.getPcodeOps()
        while opiter.hasNext():
            op = opiter.next()
            mnemonic = op.getMnemonic()
            if mnemonic == "CALL":
                opinputs = op.getInputs()
                call_target = opinputs[0]
                call_target_addr = call_target.getAddress()
                call_target_name = fm.getFunctionAt(call_target_addr).getName()

                if call_target_name == "system":
                    arg = opinputs[1]
                    sv = get_stack_var_from_varnode(func, arg)
                    if sv:
                        addr = op.getSeqnum().getTarget()
                        sink_args.append(sv.getName())
                        print("  >> {} : system({})".format(addr, sv.getName()))

                elif call_target_name == "sprintf":
                    arg = opinputs[1]
                    sv = get_stack_var_from_varnode(func, arg)
                    if sv:
                        addr = op.getSeqnum().getTarget()
                        source_args.append(sv.getName())
                        print("  >> {} : sprintf({}, ...)".format(addr, sv.getName()))

                elif call_target_name == "snprintf":
                    arg = opinputs[1]
                    sv = get_stack_var_from_varnode(func, arg)
                    if sv:
                        addr = op.getSeqnum().getTarget()
                        source_args.append(sv.getName())
                        print("  >> {} : snprintf({}, ...)".format(addr, sv.getName()))

        if len(set(sink_args) & set(source_args)) > 0:
            print("  [!] Alert: Function {} appears to contain a vulnerable `system` call pattern!".format(func.name))
            

if __name__ == "__main__":
    main()
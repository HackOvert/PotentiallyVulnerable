import argparse
import binaryninja

from os.path import isfile

DEBUG = False

sources = {
    "fgets": 0, # char *fgets(char *str, int n, FILE *stream)
    "recv":  1, # ssize_t recv(int sockfd, void *buf, size_t len, int flags);
}

sinks = {
    "printf":   0,  # int printf(const char *format, ...);
    "fprintf":  1,  # int fprintf(FILE *stream, const char *format, ...);
    "snprintf": 2,  # int snprintf(char *str, size_t size, const char *format, ...);
    "vfprintf": 1,  # int vfprintf(FILE *stream, const char *format, va_list ap);
    "vprintf":  0,  # int vprintf(const char *format, va_list ap);
    "wprintf":  0,  # int wprintf(const wchar_t *format, ...);
}

def debug_print(msg):
    if DEBUG:
        print(msg)

def main(target):
    with binaryninja.open_view(target) as bv:
        
        for sink in sinks:
            # 1. Find symbols we want to analyze
            symbols = []
            symbol_list = bv.get_symbols_by_name(sink)
            
            for symbol in symbol_list:
                if symbol.type == binaryninja.SymbolType.ImportedFunctionSymbol:
                    symbols.append(symbol)
            
            if len(symbols) <= 0:
                continue
            
            # 2. Find all cross references for each symbol
            for symbol in symbols:
                callers = bv.get_callers(symbol.address)
                if len(callers) <= 0:
                    continue
                for caller in callers:
                    func = caller.function
                    addr = caller.address

                    # 3. For each location where a sink is called, grab the parameters.
                    mlil_index = func.mlil.get_instruction_start(addr)
                    mlil_ins = func.mlil[mlil_index]
                    hlil_ins = mlil_ins.hlil
                    params = []
                    if hlil_ins.operation == binaryninja.HighLevelILOperation.HLIL_CALL:
                        params = hlil_ins.params
                    
                    # 4. Isolate `format` parameter
                    if len(params) >= (sinks[sink] + 1):
                        fparam = params[sinks[sink]]
                        if fparam.expr_type and fparam.expr_type.const:
                            debug_print("0x{:08x} : {} is SAFE!".format(hlil_ins.address, fparam))
                            continue

                        target_var = None
                        try:
                            if fparam.operation == binaryninja.HighLevelILOperation.HLIL_VAR:
                                target_var = fparam.var
                            elif fparam.operation == binaryninja.HighLevelILOperation.HLIL_DEREF:
                                target_var = fparam.src.var
                            else:
                                debug_print(">> Unsupported type: {} at 0x{:08x}".format(fparam.operation.name, hlil_ins.address))
                                continue
                        except AttributeError as e:
                            debug_print(">> ERROR: 0x{:08x} : {}\n>> {}".format(hlil_ins.address, fparam, e))
                            continue
                        
                        # 5. Locate definition (initialization) and uses of the `format` parameter
                        definitions = func.hlil.get_var_definitions(target_var)
                        uses = func.hlil.get_var_uses(target_var)
                        if len(uses) >= 1:
                            debug_print("\nFunction: {}".format(func.name))
                            for definition in definitions:
                                debug_print("Def of {} at 0x{:x} - {} ({})".format(definition.dest, definition.address, definition, definition.operation.name))
                            for use in uses:
                                debug_print("Use of {} at 0x{:x} - {} ({})".format(use.var, use.address, use.instr, use.instr.operation.name))
                                
                                # 6. Check if our `format` parameter is used in a tracked `source` function, in the tracked paramater slot
                                if use.instr.operation == binaryninja.HighLevelILOperation.HLIL_CALL:
                                    if str(use.instr.dest) in sources:
                                        source_call_ins = use.instr.dest
                                        params = source_call_ins.params
                                        target_param_index = sources[str(use.instr.src.dest)]
                                        if len(params) >= (target_param_index + 1):
                                            target_param = params[target_param_index]
                                            if type(target_param) == binaryninja.function.Variable and p == target_var:
                                                print("ALERT! - Function: {} : 0x{:X}".format(func.name, func.start))
                                
                                elif use.instr.operation == binaryninja.HighLevelILOperation.HLIL_VAR_INIT:
                                    if str(use.instr.src.dest) in sources:
                                        source_call_ins = use.instr.src
                                        params = source_call_ins.params
                                        target_param_index = sources[str(use.instr.src.dest)]
                                        if len(params) >= (target_param_index + 1):
                                            target_param = params[target_param_index]
                                            for p in target_param.prefix_operands:
                                                if type(p) == binaryninja.function.Variable and p == target_var:
                                                    print("ALERT! - Function: {} : 0x{:X}".format(func.name, func.start))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze a binary target for format string vulnerabilities.')
    parser.add_argument('target', type=str, help='full path to target binary')
    args = parser.parse_args()
    if isfile(args.target):
        main(args.target)
    else:
        print("Specified target is not valid.")

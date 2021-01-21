import binaryninja

sources = [
    'snprintf', # int snprintf ( char * s, size_t n, const char * format, ... );
    'sprintf',  # int sprintf  ( char * s, const char * format, ... );
]

sinks = [
    'system',   # int system(const char *command);
]

def main():
    with binaryninja.open_view("tdpServer") as bv:

        # Step 1. Check if our target has at least one source and one sink we care about
        source_symbols = []
        sink_symbols = []

        symbols = bv.get_symbols_of_type(binaryninja.SymbolType.ImportedFunctionSymbol)
        for symbol in symbols:
            if symbol.name in sources:
                source_symbols.append(symbol)
            elif symbol.name in sinks:
                sink_symbols.append(symbol)
        
        if (set(sinks) & set([sink.name for sink in sink_symbols])) and (set(sources) & set([source.name for source in source_symbols])):
            print("This target contains interesting source(s) and sink(s). Continuing analysis...")
        else:
            print("This target does not contain interesting source(s) and sink(s). Done.")
            return

        # Step 2. Find functions that calls at least one source and one sink
        source_callers = []
        sink_callers = []
        interesting_functions = []

        for source in source_symbols:
            func = bv.get_function_at(source.address)
            source_callers.extend(func.callers)
        
        for sink in sink_symbols:
            func = bv.get_function_at(sink.address)
            sink_callers.extend(func.callers)
        
        interesting_functions = (set(source_callers) & set(sink_callers))

        if len(interesting_functions) <= 0:
            print("\nNo interesting functions found to analyze. Done.")
            return
        else:
            print("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))
            for func in interesting_functions:
                print("  {}".format(func.name))

        # Step 3. Dig into interesting functions
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))

            source_args = []
            sink_args = []
    
            # using HLIL
            for bb in func.hlil:
                for ins in bb:
                    hlil_call_ins = None
                    if ins.operation == binaryninja.HighLevelILOperation.HLIL_CALL:
                        hlil_call_ins = ins
                    elif ins.operation == binaryninja.HighLevelILOperation.HLIL_ASSIGN and ins.src.operation == binaryninja.HighLevelILOperation.HLIL_CALL:
                        hlil_call_ins = ins.src
                    else:
                        continue
                    
                    call_target = bv.get_function_at(hlil_call_ins.dest.constant)
                    if call_target.name in sources:
                        param1 = hlil_call_ins.params[0]
                        print(" >> 0x{:x} : {}({}, ...)".format(ins.address, call_target.name, param1))
                        if param1.operation == binaryninja.HighLevelILOperation.HLIL_ADDRESS_OF:
                            param1 = param1.src
                        source_args.append(param1.var)
                    
                    elif call_target.name in sinks:
                        param1 = hlil_call_ins.params[0]
                        print(" >> 0x{:x} : {}({}, ...)".format(ins.address, call_target.name, param1))
                        if param1.operation == binaryninja.HighLevelILOperation.HLIL_ADDRESS_OF:
                            param1 = param1.src
                        sink_args.append(param1.var)
            
            if len(set(sink_args) & set(source_args)) > 0:
            	print("  [!] Alert: Function {} appears to contain a vulnerable `system` call pattern!".format(func.name))


if __name__ == "__main__":
    main()
# -*- coding: utf-8 -*-
# Full Model 1 VF Analysis
# @category Model1

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StructureDataType, FloatDataType, DWordDataType, ArrayDataType, PointerDataType
import traceback

OUTPUT = "/tmp/model1_vf/analysis_output.txt"

def run():
    f = open(OUTPUT, "w")
    
    def log(msg):
        f.write(str(msg) + "\n")
        f.flush()

    # Open transaction
    txId = currentProgram.startTransaction("Model1VFAnalysis")
    try:
        space = currentProgram.getAddressFactory().getDefaultAddressSpace()
        listing = currentProgram.getListing()
        mem = currentProgram.getMemory()
        funcMgr = currentProgram.getFunctionManager()
        refMgr = currentProgram.getReferenceManager()

        log("=" * 60)
        log("  Sega Model 1 - Virtua Fighter")
        log("  V60 (uPD70615) 24-bit addr / 16-bit data / LE")
        log("=" * 60)

        # -- Memory block info --
        log("")
        log("Memory blocks:")
        for block in mem.getBlocks():
            log("  {} : {} - {} ({} bytes)".format(
                block.getName(), block.getStart(), block.getEnd(), block.getSize()))

        # -- Hardware labels --
        log("")
        log("Creating hardware labels...")
        hw_labels = {
            0x400000: "RAMA_NVRAM",
            0x500000: "RAMB_WORK",
            0x600000: "TGP_DL0",
            0x610000: "TGP_DL1",
            0x680000: "TGP_LISTCTL",
            0x700000: "TILES",
            0x780000: "CHARS",
            0x900000: "PALETTE",
            0x910000: "COLORXLAT",
            0xC00000: "DPRAM",
            0xC40000: "UART",
            0xD00000: "CPR_ADR",
            0xD20000: "CPR_RAM",
            0xD80000: "CPR_FIFO",
            0xDC0000: "CPR_STAT",
            0xE00000: "IRQ_CTRL",
            0xE00004: "BANK_CTRL",
        }
        for addr_val, label in hw_labels.items():
            try:
                addr = space.getAddress(addr_val)
                createLabel(addr, label, True)
                log("  {} @ 0x{:06x}".format(label, addr_val))
            except Exception as e:
                log("  ERR {}: {}".format(label, e))

        # -- Define custom Sega Model 1 Data Types --
        log("")
        log("Defining structures and data types...")
        try:
            dt_manager = currentProgram.getDataTypeManager()

            # Vector3D (x, y, z)
            struct_vector3d = StructureDataType("Vector3D", 0)
            struct_vector3d.add(FloatDataType.dataType, 4, "x", "X Coordinate")
            struct_vector3d.add(FloatDataType.dataType, 4, "y", "Y Coordinate")
            struct_vector3d.add(FloatDataType.dataType, 4, "z", "Z Coordinate")
            struct_vector3d = dt_manager.addDataType(struct_vector3d, None)

            # Vector4D (x, y, z, r)
            struct_vector4d = StructureDataType("Vector4D", 0)
            struct_vector4d.add(FloatDataType.dataType, 4, "x", "X Coordinate")
            struct_vector4d.add(FloatDataType.dataType, 4, "y", "Y Coordinate")
            struct_vector4d.add(FloatDataType.dataType, 4, "z", "Z Coordinate")
            struct_vector4d.add(FloatDataType.dataType, 4, "r", "R / Radius / Scale / Homogeneous")
            struct_vector4d = dt_manager.addDataType(struct_vector4d, None)

            # Vertex3D (position, normal, color, texture coords)
            struct_vertex3d = StructureDataType("Vertex3D", 0)
            struct_vertex3d.add(struct_vector3d, 12, "pos", "3D Position")
            struct_vertex3d.add(struct_vector3d, 12, "normal", "3D Normal")
            struct_vertex3d.add(DWordDataType.dataType, 4, "color", "Vertex Color")
            struct_vertex3d.add(FloatDataType.dataType, 4, "u", "Texture U")
            struct_vertex3d.add(FloatDataType.dataType, 4, "v", "Texture V")
            struct_vertex3d = dt_manager.addDataType(struct_vertex3d, None)

            # TGP_Command (cmd, args[8])
            struct_tgp_cmd = StructureDataType("TGP_Command", 0)
            struct_tgp_cmd.add(DWordDataType.dataType, 4, "cmd", "Command ID")
            struct_tgp_cmd.add(ArrayDataType(FloatDataType.dataType, 8, 4), 32, "args", "Arguments")
            struct_tgp_cmd = dt_manager.addDataType(struct_tgp_cmd, None)

            log("  Successfully registered Vector3D, Vector4D, Vertex3D, and TGP_Command.")
        except Exception as e:
            log("  Error registering data types: {}".format(e))

        # Helper to parse PC-relative and direct targets
        def get_target(instr):
            # Check existing references first
            refs = instr.getReferencesFrom()
            if refs:
                return refs[0].getToAddress()
            
            # Check operands for [PC] or direct hex address
            num_ops = instr.getNumOperands()
            for i in range(num_ops):
                op_rep = instr.getDefaultOperandRepresentation(i)
                if "[PC]" in op_rep:
                    part = op_rep.split("[PC]")[0].strip()
                    try:
                        if part.startswith("-0x"):
                            offset = -int(part[3:], 16)
                        elif part.startswith("0x"):
                            offset = int(part[2:], 16)
                        elif part.startswith("-"):
                            offset = -int(part[1:])
                        else:
                            offset = int(part)
                        target_offset = (instr.getAddress().getOffset() + offset) & 0xFFFFFF
                        return space.getAddress(target_offset)
                    except:
                        pass
                else:
                    # Check for direct hex target like 0xfe0000 or 0x00fe0000
                    op_rep_clean = op_rep.strip()
                    if op_rep_clean.startswith("0x") or op_rep_clean.startswith("0X"):
                        try:
                            addr_val = int(op_rep_clean, 16) & 0xFFFFFF
                            return space.getAddress(addr_val)
                        except:
                            pass
            return None

        # Helper to calculate function body
        def get_function_body(entry_addr, name):
            body = AddressSet()
            body.addRange(entry_addr, entry_addr) # Force inclusion of entrypoint
            queue = [entry_addr]
            visited = set()
            
            while queue:
                curr = queue.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                
                # Trace sequential instructions
                addr = curr
                for _ in range(1000):
                    instr = listing.getInstructionAt(addr)
                    if not instr:
                        disassemble(addr)
                        instr = listing.getInstructionAt(addr)
                        if not instr:
                            break
                    
                    body.addRange(instr.getMinAddress(), instr.getMaxAddress())
                    
                    mn = instr.getMnemonicString().upper()
                    
                    # If it's an unconditional jump/branch, follow it
                    if mn == "JMP" or mn == "BR":
                        target = get_target(instr)
                        if target:
                            t_val = target.getOffset() & 0xFFFFFF
                            # Avoid crossing into another main entry point
                            if t_val not in [0xFE0000, 0x200000, 0xFFFFF0] and target not in visited:
                                queue.append(target)
                        break
                    
                    # Stop tracing on RET, RSR, HALT
                    if mn in ["RET", "RSR", "HALT"]:
                        break
                        
                    addr = addr.add(instr.getLength())
            return body

        # -- Scan game_main vector table at 0x200000 --
        log("")
        log("Scanning game_main vector table at 0x200000...")
        game_vectors = []
        addr_base = space.getAddress(0x200000)
        for idx in range(64):
            try:
                target_val = mem.getInt(addr_base.add(idx * 4)) & 0xFFFFFF
                # Validate if it points inside the ROMX range (0x200000 to 0x300000)
                if target_val >= 0x200000 and target_val < 0x300000:
                    game_vectors.append(target_val)
                    # Clear existing and create pointer data type
                    clearListing(addr_base.add(idx * 4), addr_base.add(idx * 4 + 3))
                    listing.createData(addr_base.add(idx * 4), PointerDataType.dataType)
                    createLabel(addr_base.add(idx * 4), "vector_entry_{}".format(idx), True)
                    
                    # Target points to 3D model data, label it
                    target_addr = space.getAddress(target_val)
                    createLabel(target_addr, "model_data_{}".format(idx), True)
                    log("  Found game 3D model entry {}: 0x{:06x}".format(idx, target_val))
            except Exception as e:
                break

        # Queue for function entry points to analyze
        # We start with the Reset Vector and Boot Code only.
        # game_vectors point to 3D model data, not executable V60 functions.
        func_queue = [0xFFFFF0, 0xFE0000]
        analyzed_funcs = set()

        log("")
        log("Starting control flow analysis and function creation...")

        while func_queue:
            addr_val = func_queue.pop(0)
            if addr_val in analyzed_funcs:
                continue
            analyzed_funcs.add(addr_val)

            entry_addr = space.getAddress(addr_val)
            
            # Disassemble at entry
            disassemble(entry_addr)
            
            # Create function
            fn = funcMgr.getFunctionAt(entry_addr)
            if not fn:
                name = "reset_vector" if addr_val == 0xFFFFF0 else ("boot_main" if addr_val == 0xFE0000 else ("game_main" if addr_val == 0x200000 else "sub_{:06x}".format(addr_val)))
                try:
                    body = get_function_body(entry_addr, name)
                    fn = funcMgr.createFunction(name, entry_addr, body, SourceType.USER_DEFINED)
                    if fn:
                        log("  Created function {} @ 0x{:06x}".format(name, addr_val))
                    else:
                        log("  createFunction returned None for 0x{:06x}".format(addr_val))
                except Exception as e:
                    log("  Exception creating function at 0x{:06x}: {}".format(addr_val, e))
            else:
                log("  Function already exists: {} @ 0x{:06x}".format(fn.getName(), addr_val))
                # Update body
                try:
                    body = get_function_body(entry_addr, fn.getName())
                    fn.setBody(body)
                    log("    Updated function body for {}".format(fn.getName()))
                except Exception as e:
                    log("    Exception updating body for {}: {}".format(fn.getName(), e))

            # Follow instructions inside the function to find more targets
            curr_addr = entry_addr
            # Limit loop to prevent infinite loop on bad data
            for _ in range(2000):
                instr = listing.getInstructionAt(curr_addr)
                if not instr:
                    # Try to disassemble
                    disassemble(curr_addr)
                    instr = listing.getInstructionAt(curr_addr)
                    if not instr:
                        break # Stop if we hit unreadable code
                
                mn = instr.getMnemonicString().upper()
                
                # Check if it's a Call or Jump
                is_call = "CALL" in mn or "JSR" in mn or "BSR" in mn
                is_jump = "JMP" in mn or mn.startswith("B") # BH, BE, BGT, BR, etc.
                
                if is_call or is_jump:
                    target = get_target(instr)
                    if target:
                        t_val = target.getOffset() & 0xFFFFFF
                        target_addr = space.getAddress(t_val)
                        
                        # Add reference if not already present
                        ref_type = RefType.UNCONDITIONAL_CALL if is_call else (RefType.CONDITIONAL_JUMP if mn != "JMP" and mn != "BR" else RefType.UNCONDITIONAL_JUMP)
                        try:
                            refMgr.addMemoryReference(curr_addr, target_addr, ref_type, SourceType.USER_DEFINED, 0)
                        except Exception as e:
                            log("    Error adding reference from 0x{:06x} to 0x{:06x}: {}".format(curr_addr.getOffset(), t_val, e))
                        
                        # Disassemble target
                        disassemble(target_addr)
                        
                        if is_call:
                            # Queue target as a function
                            if t_val not in analyzed_funcs and t_val not in func_queue:
                                func_queue.append(t_val)
                                log("    Discovered function target: 0x{:06x} (from call at 0x{:06x})".format(t_val, curr_addr.getOffset()))
                        else:
                            # If it's a direct jump/branch, we also disassemble it, but don't automatically make it a function
                            pass

                # If it's a terminal instruction like RET, RSR, HALT, or unconditional JMP, stop tracing this function's block
                if mn in ["RET", "RSR", "HALT"] or (mn in ["JMP", "BR"] and not "[PC]" in instr.getDefaultOperandRepresentation(0)):
                    break
                
                curr_addr = curr_addr.add(instr.getLength())

        # -- Print boot code disassembly --
        log("")
        log("=" * 60)
        log("  BOOT CODE DISASSEMBLY (first 300 instructions)")
        log("=" * 60)
        boot_addr = space.getAddress(0xFE0000)
        addr = boot_addr
        for i in range(300):
            instr = listing.getInstructionAt(addr)
            if instr:
                log("  {:06x}:  {}".format(addr.getOffset(), instr))
                addr = addr.add(instr.getLength())
            else:
                log("  {:06x}:  <undef>".format(addr.getOffset()))
                addr = addr.add(2)

        # -- Print disassembly of subroutines to identify remaining undefs --
        for name, addr_val in [("game_main", 0x200000), ("reset_vector", 0xfffff0), ("sub_fe3bfc", 0xfe3bfc), ("sub_fe3c7e", 0xfe3c7e), ("sub_ff45cc", 0xff45cc)]:
            log("")
            log("=" * 60)
            log("  DISASSEMBLY OF {} at 0x{:06x}".format(name, addr_val))
            log("=" * 60)
            addr = space.getAddress(addr_val)
            for i in range(25):
                instr = listing.getInstructionAt(addr)
                if instr:
                    log("  {:06x}:  {}".format(addr.getOffset(), instr))
                    addr = addr.add(instr.getLength())
                else:
                    try:
                        b = mem.getByte(addr) & 0xff
                        log("  {:06x}:  <undef> (raw={:02x})".format(addr.getOffset(), b))
                    except Exception as e:
                        log("  {:06x}:  <undef> (err={})".format(addr.getOffset(), e))
                    addr = addr.add(1)

        # -- Check all functions for undefined/unassembled ranges --
        log("")
        log("=" * 60)
        log("  SCANNING CREATED FUNCTIONS FOR UNDEF INSTRUCTIONS")
        log("=" * 60)
        funcs = funcMgr.getFunctions(True)
        while funcs.hasNext():
            func = funcs.next()
            if func.isExternal() or func.isThunk():
                continue
            log("Function: {} @ 0x{:06x}".format(func.getName(), func.getEntryPoint().getOffset()))
            for range_val in func.getBody():
                addr = range_val.getMinAddress()
                end_addr = range_val.getMaxAddress()
                while addr.getOffset() <= end_addr.getOffset():
                    instr = listing.getInstructionAt(addr)
                    if not instr:
                        log("  !!! Undefined/Unassembled byte at 0x{:06x}".format(addr.getOffset()))
                        addr = addr.add(1)
                    else:
                        addr = addr.add(instr.getLength())


        # -- Decompile all functions --
        log("")
        log("=" * 60)
        log("  DECOMPILATION")
        log("=" * 60)

        decompiler = DecompInterface()
        opts = DecompileOptions()
        decompiler.setOptions(opts)

        if not decompiler.openProgram(currentProgram):
            log("ERROR: Decompiler failed to open")
            return

        cf = open("/tmp/model1_vf/model1_vf_decompiled.c", "w")
        cf.write("/*\n * Sega Model 1 - Virtua Fighter\n")
        cf.write(" * NEC V60 (uPD70615) Main CPU Decompilation\n")
        cf.write(" * Boot ROM: epr-16080.4 @ 0xFC0000, epr-16081.5 @ 0xFE0000\n")
        cf.write(" * Game ROM: epr-16082.14/epr-16083.15 @ 0x200000 (interleaved)\n")
        cf.write(" */\n\n")

        functions = funcMgr.getFunctions(True)
        count = 0
        failed = 0
        while functions.hasNext() and not monitor.isCancelled():
            func = functions.next()
            if func.isExternal() or func.isThunk():
                continue
            results = decompiler.decompileFunction(func, 30, monitor)
            if results.decompileCompleted():
                code = results.getDecompiledFunction().getC()
                cf.write("/* {} @ {} */\n".format(func.getName(), func.getEntryPoint()))
                cf.write(code + "\n\n")
                count += 1
                log("")
                log("---- {} @ {} ----".format(func.getName(), func.getEntryPoint()))
                for line in code.split('\n')[:30]:
                    log("  " + line)
                if len(code.split('\n')) > 30:
                    log("  ... ({} more lines)".format(len(code.split('\n')) - 30))
            else:
                err_msg = results.getErrorMessage()
                cf.write("/* FAILED: {} - {} */\n\n".format(func.getName(), err_msg))
                failed += 1
                log("  FAILED: {} - {}".format(func.getName(), err_msg))

        cf.close()
        decompiler.dispose()
        log("")
        log("Decompiled {} functions, {} failed".format(count, failed))
        log("C output: /tmp/model1_vf/model1_vf_decompiled.c")

        log("")
        log("=" * 60)
        log("  ANALYSIS COMPLETE")
        log("=" * 60)

    except Exception as e:
        log("FATAL ERROR: " + str(e))
        traceback.print_exc(file=f)
    finally:
        currentProgram.endTransaction(txId, True)
    f.close()

run()

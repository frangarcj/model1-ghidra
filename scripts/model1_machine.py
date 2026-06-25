#!/usr/bin/env python3
"""
Sega Model 1 Machine Builder for Ghidra
========================================
Assembles a complete V60 memory image from individual ROM files,
matching MAME's model1_mem() address map, and runs Ghidra headless
analysis with the V60 processor module.

Memory Map (from MAME model1.cpp):
  0x000000 - 0x0FFFFF  ROMA  (1MB) - Main program ROM area
  0x100000 - 0x1FFFFF  ROMO  (1MB) - Banked ROM
  0x200000 - 0x2FFFFF  ROMX  (1MB) - Extended program ROM
  0x400000 - 0x40FFFF  RAMA  (64KB) - NVRAM
  0x500000 - 0x53FFFF  RAMB  (256KB) - Work RAM
  0x600000 - 0x61FFFF  TGP   (128KB) - Display lists
  0x700000 - 0x7FFFFF  SCR   - Tile/char generator
  0x900000 - 0x91BFFF  COL   - Palette + color xlat
  0xC00000 - 0xC00FFF  I/O   - Dual-port RAM
  0xD00000 - 0xDFFFFF  CPR   - Copro (TGP) interface
  0xE00000 - 0xE0000F  GLUE  - IRQ + bank control
  0xF80000 - 0xFFFFFF  ROM0  (512KB) - Boot ROM area

V60 address space: 24-bit (16MB), little-endian, 16-bit data bus
Reset vector: PC = 0xFFFFF0 (0xFFFFFFF0 masked to 24 bits)

VF ROM layout (from MAME ROM_START(vf)):
  epr-16082.14 @ 0x200000 (LOAD16_BYTE even, 512KB)
  epr-16083.15 @ 0x200001 (LOAD16_BYTE odd, 512KB)
  epr-16080.4  @ 0xFC0000 (LOAD, 128KB)
  epr-16081.5  @ 0xFE0000 (LOAD, 128KB)
"""
import os
import struct
import subprocess
import sys

# ── Configuration ─────────────────────────────────────────────────────
ROM_DIR     = "/Users/frangar/Fun/model/roms/vf"
OUTPUT_DIR  = "/tmp/model1_vf"
FLAT_BIN    = os.path.join(OUTPUT_DIR, "model1_vf.bin")
GHIDRA_HOME = "/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC"
SLEIGH_COMP = os.path.join(GHIDRA_HOME, "support", "sleigh")
ANALYZE_HL  = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
SLASPEC     = os.path.join(GHIDRA_HOME, "Ghidra/Processors/V60/data/languages/v60.slaspec")
TGP_SLASPEC = os.path.join(GHIDRA_HOME, "Ghidra/Processors/MB86233/data/languages/mb86233.slaspec")
POST_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Model1VFAnalysis.py")

# 24-bit address space + banked data ROMs = 20 MB
ADDR_SPACE_SIZE = 0x1400000

# ── ROM definitions (from MAME ROM_START(vf)) ────────────────────────
# (filename, load_offset, size, load_type)
# load_type: "byte" = ROM_LOAD (raw bytes), "16even" / "16odd" = ROM_LOAD16_BYTE
ROMS = [
    # Main program ROMs (interleaved 16-bit)
    ("epr-16082.14", 0x200000, 0x80000, "16even"),
    ("epr-16083.15", 0x200001, 0x80000, "16odd"),
    # Boot ROMs (straight load)
    ("epr-16080.4",  0xFC0000, 0x20000, "byte"),
    ("epr-16081.5",  0xFE0000, 0x20000, "byte"),
]

# Data ROMs (program data, interleaved 16-bit, at 0x1000000+, would exceed 16MB)
# These go into the banked area if bank is switched; skip for boot analysis.
DATA_ROMS = [
    ("mpr-16084.6",  0x1000000, 0x80000, "16even"),
    ("mpr-16085.7",  0x1000001, 0x80000, "16odd"),
    ("mpr-16086.8",  0x1100000, 0x80000, "16even"),
    ("mpr-16087.9",  0x1100001, 0x80000, "16odd"),
    ("mpr-16088.10", 0x1200000, 0x80000, "16even"),
    ("mpr-16089.11", 0x1200001, 0x80000, "16odd"),
    ("mpr-16090.12", 0x1300000, 0x80000, "16even"),
    ("mpr-16091.13", 0x1300001, 0x80000, "16odd"),
]

# ── Memory map region definitions for Ghidra annotations ─────────────
MEMORY_REGIONS = [
    # (name, start, end, type)
    ("ROMA",  0x000000, 0x0FFFFF, "rom"),
    ("ROMO",  0x100000, 0x1FFFFF, "rom"),
    ("ROMX",  0x200000, 0x2FFFFF, "rom"),
    ("RAMA",  0x400000, 0x40FFFF, "ram"),
    ("RAMB",  0x500000, 0x53FFFF, "ram"),
    ("TGP_DL0", 0x600000, 0x60FFFF, "ram"),
    ("TGP_DL1", 0x610000, 0x61FFFF, "ram"),
    ("LISTCTL", 0x680000, 0x680003, "io"),
    ("TILES",   0x700000, 0x70FFFF, "io"),
    ("CHARS",   0x780000, 0x7FFFFF, "io"),
    ("PALETTE", 0x900000, 0x903FFF, "ram"),
    ("COLORXL", 0x910000, 0x91BFFF, "ram"),
    ("DPRAM",   0xC00000, 0xC00FFF, "io"),
    ("UART",    0xC40000, 0xC40003, "io"),
    ("CPR_ADR", 0xD00000, 0xD1FFFF, "io"),
    ("CPR_RAM", 0xD20000, 0xD3FFFF, "io"),
    ("CPR_FIFO",0xD80000, 0xD9FFFF, "io"),
    ("CPR_STAT",0xDC0000, 0xDDFFFF, "io"),
    ("GLUE",    0xE00000, 0xE0000F, "io"),
    ("ROM0",    0xF80000, 0xFFFFFF, "rom"),
    ("ROMO_BK0",0x1000000, 0x10FFFFF, "rom"),
    ("ROMO_BK1",0x1100000, 0x11FFFFF, "rom"),
    ("ROMO_BK2",0x1200000, 0x12FFFFF, "rom"),
    ("ROMO_BK3",0x1300000, 0x13FFFFF, "rom"),
]

# V60 reset vector (0xFFFFFFF0 masked to 24 bits)
RESET_VECTOR = 0xFFFFF0


def assemble_flat_binary():
    """Assemble all ROMs into a flat binary image."""
    print(f"[*] Creating {ADDR_SPACE_SIZE // (1024*1024)}MB flat binary...")
    # Fill with 0xFF (like unprogrammed flash/EPROM)
    image = bytearray(b'\xff' * ADDR_SPACE_SIZE)

    for filename, offset, size, load_type in ROMS + DATA_ROMS:
        rom_path = os.path.join(ROM_DIR, filename)
        if not os.path.exists(rom_path):
            print(f"[!] WARNING: ROM file not found: {rom_path}")
            continue

        with open(rom_path, "rb") as f:
            rom_data = f.read()

        actual_size = len(rom_data)
        if actual_size != size:
            print(f"[!] WARNING: {filename} size {actual_size:#x} != expected {size:#x}")

        if load_type == "byte":
            # Straight byte load
            target_offset = offset & 0x1FFFFFF
            end = min(target_offset + actual_size, ADDR_SPACE_SIZE)
            copy_len = end - target_offset
            image[target_offset:target_offset + copy_len] = rom_data[:copy_len]
            print(f"    {filename} -> {target_offset:#08x}-{target_offset + copy_len - 1:#08x} (byte load, {copy_len:#x} bytes)")

        elif load_type == "16even":
            # ROM_LOAD16_BYTE even bytes (offset is even)
            base = offset & 0x1FFFFFE  # Support address space extension
            for i in range(min(actual_size, size)):
                addr = base + i * 2
                if addr < ADDR_SPACE_SIZE:
                    image[addr] = rom_data[i]
            print(f"    {filename} -> {base:#08x} (16-bit even, {actual_size:#x} bytes -> {actual_size * 2:#x} span)")

        elif load_type == "16odd":
            # ROM_LOAD16_BYTE odd bytes (offset is odd)
            base = (offset & 0x1FFFFFE) + 1
            for i in range(min(actual_size, size)):
                addr = base + i * 2
                if addr < ADDR_SPACE_SIZE:
                    image[addr] = rom_data[i]
            print(f"    {filename} -> {base:#08x} (16-bit odd, {actual_size:#x} bytes -> {actual_size * 2:#x} span)")

    return bytes(image)


def check_reset_vector(image):
    """Read and display what's at the V60 reset vector address."""
    print(f"\n[*] V60 Reset Vector at {RESET_VECTOR:#08x}:")
    # Show bytes at reset vector
    vec_bytes = image[RESET_VECTOR:RESET_VECTOR + 16]
    hex_str = " ".join(f"{b:02x}" for b in vec_bytes)
    print(f"    Bytes: {hex_str}")


def compile_sleigh():
    """Compile both the V60 and MB86233 TGP Sleigh specifications."""
    success = True
    for spec_path in [SLASPEC, TGP_SLASPEC]:
        if not os.path.exists(spec_path):
            print(f"[!] WARNING: Sleigh file not found: {spec_path}")
            continue
        print(f"\n[*] Compiling Sleigh spec: {spec_path}")
        try:
            result = subprocess.run([SLEIGH_COMP, spec_path], capture_output=True, text=True, check=True)
            print(f"    Sleigh compilation successful for {os.path.basename(spec_path)}.")
        except subprocess.CalledProcessError as e:
            print(f"    ERROR compiling Sleigh {os.path.basename(spec_path)}: {e}")
            if e.stderr:
                # Show only last 20 lines of errors
                lines = e.stderr.strip().split('\n')
                for line in lines[-20:]:
                    print(f"    {line}")
            success = False
    return success


def run_ghidra_analysis(bin_path):
    """Run Ghidra headless analysis on the assembled binary."""
    project_dir = os.path.join(OUTPUT_DIR, "ghidra_project")
    project_name = "model1_vf"

    # Clean old project
    if os.path.exists(project_dir):
        import shutil
        shutil.rmtree(project_dir)
    os.makedirs(project_dir, exist_ok=True)

    print(f"\n[*] Running Ghidra headless analysis...")
    print(f"    Binary: {bin_path}")
    print(f"    Processor: V60:LE:32:default")
    print(f"    PostScript: {POST_SCRIPT}")

    cmd = [
        ANALYZE_HL,
        project_dir, project_name,
        "-import", bin_path,
        "-processor", "V60:LE:32:default",
        "-noanalysis",  # We'll do manual analysis in the script
        "-postScript", POST_SCRIPT,
        "-deleteProject",
        "-log", os.path.join(OUTPUT_DIR, "ghidra.log"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Show only important Ghidra messages
        if result.stdout:
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                if any(k in stripped for k in ['SCRIPT:', 'REPORT:', 'SyntaxError', 'Error', 'Exception']):
                    print(f"    {stripped}")

        # Show stderr errors
        if result.stderr:
            for line in result.stderr.strip().split('\n'):
                if 'SyntaxError' in line or 'Error' in line or 'Exception' in line:
                    print(f"    [ERR] {line.strip()}")

        if result.returncode != 0:
            print(f"\n[!] Ghidra exited with code {result.returncode}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print("[!] Ghidra analysis timed out (120s)")
        return False


def run_tgp_analysis(tgp_bin_path):
    """Run Ghidra headless analysis on the TGP (MB86233) binary code."""
    project_dir = os.path.join(OUTPUT_DIR, "ghidra_project_tgp")
    project_name = "model1_tgp"

    # Clean old project
    if os.path.exists(project_dir):
        import shutil
        shutil.rmtree(project_dir)
    os.makedirs(project_dir, exist_ok=True)

    print(f"\n[*] Running Ghidra headless analysis on TGP DSP Code...")
    print(f"    Binary: {tgp_bin_path}")
    print(f"    Processor: MB86233:LE:32:default")

    # Headless Ghidra import and auto-disassembly
    cmd = [
        ANALYZE_HL,
        project_dir, project_name,
        "-import", tgp_bin_path,
        "-processor", "MB86233:LE:32:default",
        # Use default analysis to auto-disassemble and identify subroutines
        "-deleteProject",
        "-log", os.path.join(OUTPUT_DIR, "ghidra_tgp.log"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print("    TGP analysis complete.")
        return result.returncode == 0
    except Exception as e:
        print(f"    Failed to run TGP analysis: {e}")
        return False


def main():
    print("=" * 70)
    print("  Sega Model 1 - Virtua Fighter Machine Builder")
    print("  V60 (NEC uPD70615) + MB86233 TGP")
    print("=" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Step 1: Assemble the flat binary
    print("\n── Step 1: Assemble ROM image ──────────────────────────────────────")
    image = assemble_flat_binary()
    check_reset_vector(image)

    # Write flat binary
    with open(FLAT_BIN, "wb") as f:
        f.write(image)
    print(f"\n    Flat binary written: {FLAT_BIN} ({len(image):#x} bytes)")

    # Step 2: Compile Sleigh
    print("\n── Step 2: Compile Sleigh specification ────────────────────────────")
    if not compile_sleigh():
        print("[!] FATAL: Sleigh compilation failed. Cannot continue.")
        sys.exit(1)

    # Step 3: Run Ghidra CPU analysis
    print("\n── Step 3: Ghidra headless analysis ────────────────────────────────")
    success = run_ghidra_analysis(FLAT_BIN)

    # Optional Step 3b: Run TGP analysis if tgp.bin is found
    tgp_bin = os.path.join(ROM_DIR, "tgp.bin")
    if os.path.exists(tgp_bin):
        print("\n── Step 3b: TGP Microcode analysis ────────────────────────────────")
        run_tgp_analysis(tgp_bin)
    else:
        # Check in the output directory too
        tgp_bin_opt = os.path.join(OUTPUT_DIR, "tgp.bin")
        if os.path.exists(tgp_bin_opt):
            print("\n── Step 3b: TGP Microcode analysis ────────────────────────────────")
            run_tgp_analysis(tgp_bin_opt)

    # Step 4: Read and display the analysis results
    print("\n── Step 4: Analysis Results ─────────────────────────────────────────")
    analysis_output = os.path.join(OUTPUT_DIR, "analysis_output.txt")
    if os.path.exists(analysis_output):
        with open(analysis_output, "r") as f:
            print(f.read())
    else:
        print("[!] No analysis output found. The Ghidra script may have failed.")
        print("    Check ghidra.log for errors.")

    # Show decompiled code if it exists
    decompiled_path = os.path.join(OUTPUT_DIR, "model1_vf_decompiled.c")
    if os.path.exists(decompiled_path):
        print("\n── Decompiled C output ─────────────────────────────────────────────")
        with open(decompiled_path, "r") as f:
            content = f.read()
            if content.strip():
                print(content)
            else:
                print("[!] Decompiled file is empty.")

    print("\n" + "=" * 70)
    if success:
        print("  ✓ Machine build and analysis completed successfully!")
    else:
        print("  ✗ Analysis encountered errors. Check logs in:")
        print(f"    {OUTPUT_DIR}/ghidra.log")
        print(f"    {OUTPUT_DIR}/script.log")
    print("=" * 70)


if __name__ == "__main__":
    main()

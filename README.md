# IDA-FastAnalysis

A (WIP) IDA **9.x, 8.x** plugin that speeds up the initial binary auto analysis through caching and multithreaded analysis.

Below represents where optimizations by IDA-FastAnalysis can currently be applied:


| IDA Version | Supported targets |
|-------------|-------------------|
| 9.x         | x64, ARM64        |
| 8.x         | x64               |

## TODO
- [ ] Support for Linux versions of IDA
- [ ] "Sanity check" to ensure disassembly isn't affected
- [ ] Designate a test binary for benchmarks

## How it works

### Optimization #1: Write xref lookups
In the function `reg_finder_emulate_mem_read`, IDA repeatedly searches for write-to-data cross references throughout the entire target binary in some stages of auto analysis, to check if a value at a certain address is a constant.
This process takes a significant amount of time, slowing down analysis, especially for large binary files (~50MB+)

Below is a rough pseudocode of the function called by `emulate_mem_read`. It is called mostly for the same few addresses during analysis (like the security cookie in many programs).

```c++
// Scans target binary looking for a data write xref to
// target_addr (very slow)
bool has_write_dref(ea_t target_addr) {
    xrefblk_t xb{};
    
    // Finds the first cross reference to target_addr
    if (!xb.first_to(target_addr, XREF_FLOW))
        return false;
    
    // Keeps scanning until a DATA xref is found
    // that writes to the target address 
    while (xb.type != dr_W) {
        if (!xb.next_to())
            return false;
    }
    
    return true;
}
```

IDA-FastAnalysis overrides this functionality and instead creates a pre-computed set of all addresses that have a write xref to them, resulting in significantly faster analysis speeds (up to 200x faster during some of the most intensive analysis stages for x64 targets!)

### Optimization #2: `get_bytes`
Overrides the internal functionality of `get_bytes`, another function called frequently during analysis. FastAnalysis caches `.data` and `.rdata` section contents, with special cases for retrieving small 8 and 16-byte buffers for efficiency.

> [!WARNING]  
> Due to how this optimization currently works, patching the binary while auto analysis is running can lead to corruption or inaccurate disassembly.

## Building

To build for IDA 8.x, the environment variable `IDA_8_SDK` must be defined. It must point to a directory with `lib` and `include` directories and contents from your IDA SDK installation.

If `IDA_8_SDK` is not defined, only the 9.x version can be built.

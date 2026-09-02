# IDA-FastAnalysis

A (WIP) IDA **9.2-9.4, 8.3** plugin that speeds up the initial binary auto analysis through caching and multithreaded analysis.

## Update: The analysis slowdown targeted by this plugin has been [fixed for MetaPC in the IDA 9.4 beta](https://docs.hex-rays.com/release-notes/9_4beta#performance)! The plugin will not be needed when analyzing x86/x64 binaries in IDA 9.4+.   
However, FastAnalysis is still usable for ARM64 on this version. 

Below represents where optimizations by IDA-FastAnalysis can currently be applied:


| IDA Version | IDA Platform                  | Supported targets |
|-------------|-------------------------------|-------------------|
| 9.4         | Windows, Linux, Apple Silicon | ARM64             |
| 9.2-9.3     | Windows, Linux                | x64, ARM64        |
| 8.3         | Windows                       | x64               |

## TODO
- [x] Support for Linux versions of IDA
- [ ] "Sanity check" to ensure disassembly isn't affected
- [ ] Designate a test binary for benchmarks

## How it works

### Optimization #1: Write xref lookups
IDA repeatedly searches for write-to-data cross-references throughout the entire target binary in some stages of auto analysis, to check if a value at a certain address is a constant.
This process takes a significant amount of time, slowing down analysis, especially for large binary files (~50MB+)

Below is a rough pseudocode of the function. It is called mostly for the same few addresses during analysis (like the security cookie in many programs).

```c++
// Scans target binary looking for a data write xref to
// target_addr (very slow)
bool has_write_dref(ea_t target_addr) {
    xrefblk_t xb{};
    
    // Finds the first cross reference to target_addr
    if (!xb.first_to(target_addr, XREF_DATA))
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

IDA-FastAnalysis overrides this functionality and instead initially creates a cache of all write xrefs, resulting in significantly faster analysis speeds (up to 200x faster during some of the most intensive analysis stages for x64 targets!)

> [!WARNING]  
> Due to how this optimization currently works, patching the binary while auto analysis is running can lead to corruption or inaccurate disassembly.

## Building

To build for IDA 8.x, the environment variable `IDA_8_SDK` must be defined. It must point to a directory with `lib` and `include` directories and contents from your IDA SDK installation.

If `IDA_8_SDK` is not defined, only the 9.x version can be built.

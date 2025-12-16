# IDA-FastAnalysis

A (WIP) **IDA 9.2** plugin that speeds up the initial binary auto analysis through caching and multithreaded analysis.

Currently, this plugin for the Windows version of [IDA Pro](https://hex-rays.com/ida-pro) supports the analysis of x64 (x86-64) binaries.

## TODO
- [ ] ARM64 support
- [ ] Support for Linux versions of IDA
- [ ] Compile a test binary for benchmarks

## How it works

### Optimization #1: Write xref lookups
For unknown reasons, IDA frequently searches for write-to-data cross references throughout the entire target binary in some stages of auto analysis.
This process takes a significant amount of time, slowing down analysis, especially for large binary files (~50MB+).

Rough pseudocode:

```c++
// Scans target binary looking for a data write xref to
// target_addr (very slow)
bool has_write_dref(ea_t target_addr) {
    xrefblk_t xb{};
    
    // Finds the first cross reference to target_addr
    if (!xb.first_to(target_addr, XREF_FLOW))
        return false;
    
    // Keeps scanning until a DATA_XREF is found
    // that writes to the target address 
    while (xb.type != dr_W) {
        if (!xb.next_to())
            return false;
    }
    
    return true;
}
```

IDA-FastAnalysis overrides this functionality and instead creates a pre-computed set of all addresses that have a write xref to them, resulting in significantly faster analysis speeds (up to 200x faster during some of the most intensive analysis stages, like `AC` and `FL`!) 



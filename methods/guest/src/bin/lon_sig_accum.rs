#![no_main]

// `#[lez_program]` generates `pub fn main()` in the program crate; this binary
// is only the zkVM entry point that calls it.
risc0_zkvm::guest::entry!(lon_sig_accum_program::main);

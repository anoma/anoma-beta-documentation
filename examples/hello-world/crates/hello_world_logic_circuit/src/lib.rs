// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_counter_elf_id() {
    use hello_world_methods::{HELLO_WORLD_GUEST_ELF, HELLO_WORLD_GUEST_ID};
    // Write the elf binary to a file
    std::fs::write(
        "../../hello_world_library/elf/hello-world-guest.bin",
        HELLO_WORLD_GUEST_ELF,
    )
    .expect("Failed to write counter-guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!("HELLO_WORLD_GUEST_ID: {:?}", Digest::from(HELLO_WORLD_GUEST_ID));
}

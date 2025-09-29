use risc0_zkvm::guest::env;
use hello_world_witness::{HelloWorldWitness, LogicCircuit};

fn main() {
    // read the input
    let witness: HelloWorldWitness = env::read();

    // process constraints
    let instance = witness.constrain();

    // write public output to the journal
    env::commit(&instance);
}

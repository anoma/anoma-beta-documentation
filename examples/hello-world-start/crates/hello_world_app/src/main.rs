use crate::init::{generate_ephemeral_hello_world_resource, generate_persistent_hello_world_resource};
use crate::util::{generate_compliance_proof, generate_logic_proofs};
use arm::action::Action;
use arm::delta_proof::DeltaWitness;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::transaction::{Delta, Transaction};

mod init;
mod util;

fn create_transaction() -> Transaction {
    // <!-- Creating the ephemeral hello_world resource -->
    // Create required keypair
    let (eph_nf_key, eph_nf_key_cm) = NullifierKey::random_pair();
    
    // Create the resource
    let consumed_hello_world = generate_ephemeral_hello_world_resource(eph_nf_key_cm);

    // <!-- Create the persistent hello_world resource -->
    // Create required keypair
    let (_nf_key, nf_key_cm) = NullifierKey::random_pair();

    // Create the resource
    let created_hello_world = generate_persistent_hello_world_resource(&consumed_hello_world, &eph_nf_key, &nf_key_cm);

    // <!-- Create the compliance proof -->
    let (compliance_unit, rcv) = generate_compliance_proof(
        consumed_hello_world.clone(),
        eph_nf_key.clone(),
        MerklePath::default(),
        created_hello_world.clone(),
    );

    // <!-- Create the logic proofs -->
    let logic_verifier_inputs = generate_logic_proofs(
        consumed_hello_world.clone(),
        eph_nf_key,
        created_hello_world.clone(),
    );

    // <!-- Create the transaction actions -->
    let action = Action::new(vec![compliance_unit], logic_verifier_inputs);

    // <!-- Create the delta proof -->
    let delta_witness = DeltaWitness::from_bytes(&rcv);
    
    // <!-- Create the transaction -->
    let mut tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();

    // verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }

    tx
}

fn main() {
    let tx = create_transaction();
    // let _ = submit_transaction(tx);
    println!("tx: {:?}", tx);
    println!("hello world yippie");
}

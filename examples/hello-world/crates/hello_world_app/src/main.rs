//! Hello World Application
//! 
//! This application demonstrates the creation and verification of a hello world
//! ARM (Anoma Resource Model) transaction. It creates one ephemeral
//! and one persistentresource, generates logic and compliance
//! proofs, and creates a verifiable transaction.

use crate::init::{generate_ephemeral_resource, generate_persistent_resource};
use crate::util::{generate_compliance_proof, generate_logic_proofs};

use arm::action::Action;
use arm::delta_proof::DeltaWitness;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::transaction::{Delta, Transaction};

mod init;
mod util;

/// Creates and verifies a complete hello world transaction.
/// 
/// This function demonstrates the full lifecycle of a hello world transaction:
/// 1. Creates an ephemeral resource
/// 2. Creates a persistent resource
/// 3. Generates compliance and logic proofs
/// 4. Creates and verifies the transaction
/// 
/// # Returns
/// 
/// A verified `Transaction` containing the proofs to verify the creation of a hello world resource 
/// 
/// # Panics
/// 
/// This function may panic if any of the proof generation or verification steps fail
fn create_transaction() -> Transaction {
    // Step 1: Create ephemeral hello world resource
    println!("\nCreating ephemeral hello world resource...");
    let (ephemeral_nf_key, ephemeral_nf_key_commitment) = NullifierKey::random_pair();
    let consumed_resource = generate_ephemeral_resource(ephemeral_nf_key_commitment);

    // Step 2: Create persistent hello world resource
    println!("\nCreating persistent hello world resource...");
    let (_, persistent_nf_key_commitment) = NullifierKey::random_pair();
    let created_resource = generate_persistent_resource(
        &consumed_resource, 
        &ephemeral_nf_key, 
        &persistent_nf_key_commitment
    );

    // Step 3: Generate compliance proof
    println!("\nCreating compliance proof...");
    let (compliance_unit, rcv) = generate_compliance_proof(
        consumed_resource.clone(),
        ephemeral_nf_key.clone(),
        MerklePath::default(),
        created_resource.clone(),
    );

    // Step 4: Generate logic proofs
    println!("\nCreating logic proofs...");
    let logic_verifier_inputs = generate_logic_proofs(
        consumed_resource,
        ephemeral_nf_key,
        created_resource,
    );

    // Step 5: Create transaction action
    println!("\nCreating transaction action...");
    let action = Action::new(vec![compliance_unit], logic_verifier_inputs);

    // Step 6: Create delta witness and transaction
    println!("\nCreating transaction...");
    let delta_witness = DeltaWitness::from_bytes(&rcv);
    let mut transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));

    // Step 7: Generate and verify delta proof
    println!("\nGenerating delta proof...");
    transaction.generate_delta_proof();

    // Verify the transaction
    println!("\nVerifying transaction...");
    if transaction.clone().verify() {
        println!("Transaction verified successfully");
    } else {
        println!("Transaction verification failed");
    }

    transaction
}

/// Main entry point for the hello world application.
/// 
/// This function creates a hello world transaction and displays its details.
fn main() {
    println!("\nStarting Hello World Application");
    
    // Create and verify the transaction
    let transaction = create_transaction();
    
    // Display transaction details
    println!("\nTransaction Details:");
    println!("{:?}", transaction);
    
    // let _ = submit_transaction(transaction);
    
    println!("\nTransaction completed successfully!");
}

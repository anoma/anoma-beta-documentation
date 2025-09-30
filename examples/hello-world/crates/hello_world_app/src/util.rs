//! Utility functions for generating compliance and logic proofs.
//! 
//! This module provides functions for creating the required cryptographic proofs. It handles
//! both compliance proofs and logic proofs.

use arm::action_tree::MerkleTree;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::logic_proof::{LogicProver, LogicVerifier};
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use hello_world_library::HelloWorldLogic;

/// Generates a compliance proof for resource consumption and creation.
/// 
/// This function creates a compliance witness that proves the proper consumption
/// of an ephemeral resource and creation of a persistent resource. The compliance
/// proof ensures that the transaction follows the ARM protocol rules.
/// 
/// # Arguments
/// 
/// * `consumed_resource` - The ephemeral resource that was consumed
/// * `nf_key` - The nullifier key used to consume the resource
/// * `merkle_path` - The merkle path for the consumed resource in the state tree
/// * `created_resource` - The persistent resource that was created
/// 
/// # Returns
/// 
/// A tuple containing:
/// * `ComplianceUnit` - The compliance proof unit
/// * `Vec<u8>` - The RCV (Resource Commitment Vector) bytes
/// 
/// # Panics
/// 
/// This function may panic if the compliance witness creation fails
pub fn generate_compliance_proof(
    consumed_resource: Resource,
    nullifier_key: NullifierKey,
    merkle_path: MerklePath,
    created_resource: Resource,
) -> (ComplianceUnit, Vec<u8>) {
    // Create compliance witness from resources and merkle path
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_resource,
        nullifier_key,
        merkle_path,
        created_resource,
    );
    
    // Generate compliance unit from the witness
    let compliance_unit = ComplianceUnit::create(&compliance_witness);
    
    // Return both the compliance unit and RCV bytes
    (compliance_unit, compliance_witness.rcv)
}

/// Generates logic proofs for both consumed and created hello world resources.
/// 
/// This function creates zero-knowledge proofs that verify the correctness of
/// the hello world resource logic. It generates separate proofs for:
/// 1. The consumption of the ephemeral resource (is_consumed = true)
/// 2. The creation of the persistent resource (is_consumed = false)
/// 
/// The proofs use a merkle tree to establish the relationship between the
/// consumed and created resources.
/// 
/// # Arguments
/// 
/// * `consumed_resource` - The ephemeral resource that was consumed
/// * `nullifier_key` - The nullifier key used to consume the resource
/// * `created_resource` - The persistent resource that was created
/// 
/// # Returns
/// 
/// A vector containing two `LogicVerifier` instances:
/// * First element: Proof for the consumed resource
/// * Second element: Proof for the created resource
/// 
/// # Panics
/// 
/// This function may panic if:
/// * The nullifier generation fails
/// * The merkle path generation fails
/// * The logic proof generation fails
pub fn generate_logic_proofs(
    consumed_resource: Resource,
    nullifier_key: NullifierKey,
    created_resource: Resource,
) -> Vec<LogicVerifier> {
    // Generate nullifier for consumed resource and commitment for created resource
    let consumed_resource_nullifier = consumed_resource.nullifier(&nullifier_key).unwrap();
    let created_resource_commitment = created_resource.commitment();

    // Create action tree with both nullifier and commitment
    let action_tree = MerkleTree::new(vec![consumed_resource_nullifier, created_resource_commitment]);

    // Generate merkle path for consumed resource
    let consumed_resource_path = action_tree.generate_path(&consumed_resource_nullifier).unwrap();

    // Create and prove logic for consumed resource (is_consumed = true)
    let consumed_resource_logic = HelloWorldLogic::new(
        true,
        consumed_resource.clone(),
        consumed_resource_path.clone(),
        nullifier_key.clone()
    );
    let consumed_logic_proof = consumed_resource_logic.prove();

    // Generate merkle path for created resource
    let created_resource_path = action_tree.generate_path(&created_resource_commitment).unwrap();
    
    // Create and prove logic for created resource (is_consumed = false)
    let created_resource_logic = HelloWorldLogic::new(
        false,
        created_resource,
        created_resource_path,
        nullifier_key,
    );
    let created_logic_proof = created_resource_logic.prove();

    // Return both proofs in order: consumed first, then created
    vec![consumed_logic_proof, created_logic_proof]
}

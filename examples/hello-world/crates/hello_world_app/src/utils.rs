//! Utility functions all purposes related to ARM transaction creation.
//! 
//! This module provides functions for creating the required resources and cryptographic proofs. It handles
//! both compliance proofs and logic proofs.

use arm::action_tree::MerkleTree;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::logic_proof::{LogicProver, LogicVerifier};
use arm::merkle_path::MerklePath;
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::resource::Resource;
use hello_world_library::HelloWorldLogic;
use rand::Rng;

/// Converts a hello world value to a 32-byte value reference.
/// 
/// The value is left-aligned and right-padded with zeros to create
/// a 32-byte array suitable for use as a value reference in the
/// hello world resource system.
/// 
/// # Arguments
/// 
/// * `value` - The u128 value to convert
/// 
/// # Returns
/// 
/// A 32-byte vector representing the value reference
pub fn convert_hello_world_to_value_ref(value: u128) -> Vec<u8> {
    let mut arr = [0u8; 32];
    let bytes = value.to_le_bytes();
    arr[..16].copy_from_slice(&bytes); // left-align, right-pad with 0
    arr.to_vec()
}

/// Generates an ephemeral hello world resource with a random nonce.
/// 
/// This function creates a temporary resource that can be consumed
/// to generate a persistent resource. The resource includes:
/// - A logic reference from the verifying key
/// - A "Hello World" label
/// - A zero value reference
/// - A random 32-byte nonce
/// 
/// # Arguments
/// 
/// * `nk_commitment` - The nullifier key commitment for the resource
/// 
/// # Returns
/// 
/// A new ephemeral `Resource` ready for consumption
pub fn generate_ephemeral_resource(nk_commitment: NullifierKeyCommitment) -> Resource {
    // Create logic reference from the verifying key
    let logic_ref = HelloWorldLogic::verifying_key_as_bytes();

    // Generate random components for the resource
    let mut rng = rand::thread_rng();
    let mut label_ref = [0u8; 32];
    let hello_world_bytes = b"Hello World";
    label_ref[..hello_world_bytes.len()].copy_from_slice(hello_world_bytes);
    
    // Set initial value to 0 for ephemeral resource
    let value_ref = convert_hello_world_to_value_ref(0u128);

    // Generate random nonce for uniqueness
    let nonce: [u8; 32] = rng.gen();

    Resource::create(
        logic_ref,
        label_ref.to_vec(),
        1,
        value_ref,
        true,
        nonce.to_vec(),
        nk_commitment,
    )
}

/// Initializes a persistent hello world resource from an ephemeral resource.
/// 
/// This function transforms an ephemeral resource into a persistent one by:
/// - Setting the resource as non-ephemeral
/// - Renewing its randomness
/// - Resetting the nonce from the ephemeral resource
/// - Setting the value reference to 1 (initial hello world value)
/// - Updating the nullifier key commitment
/// 
/// # Arguments
/// 
/// * `consumed_resource` - The ephemeral resource that was consumed
/// * `ephemeral_nf_key` - The nullifier key from the ephemeral resource
/// * `nf_key_cm` - The new nullifier key commitment
/// 
/// # Returns
/// 
/// A new persistent `Resource` ready for use
pub fn generate_persistent_resource(
    consumed_resource: &Resource,
    eph_nf_key: &NullifierKey,
    nf_key_cm: &NullifierKeyCommitment,
) -> Resource {
    // Start with a clone of the consumed ephemeral resource
    let mut init_hello_world = consumed_resource.clone();
    
    // Transform to persistent resource
    init_hello_world.is_ephemeral = false;
    init_hello_world.reset_randomness();
    init_hello_world.set_nonce_from_nf(consumed_resource, eph_nf_key);
    
    // Set initial value to 1 for persistent resource
    init_hello_world.set_value_ref(convert_hello_world_to_value_ref(1u128));
    
    // Update nullifier key commitment
    init_hello_world.set_nf_commitment(nf_key_cm.clone());
    
    init_hello_world
}


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
/// * `Vec<u8>` - The RCV (Random Commitment Value) bytes
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

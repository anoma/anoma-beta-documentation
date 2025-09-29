use arm::logic_proof::LogicProver;
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

use arm::logic_proof::LogicProver;
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::resource::Resource;
use hello_world_library::HelloWorldLogic;
use rand::Rng;

pub fn convert_hello_world_to_value_ref(value: u128) -> Vec<u8> {
    let mut arr = [0u8; 32];
    let bytes = value.to_le_bytes();
    arr[..16].copy_from_slice(&bytes); // left-align, right-pad with 0
    arr.to_vec()
}

// It creates a random label reference and a nullifier key for the
// ephermeral hello_world resource.
pub fn generate_ephemeral_hello_world_resource(nf_key_cm: NullifierKeyCommitment) -> Resource {
    let mut rng = rand::thread_rng();
    let mut label_ref = [0u8; 32];
    let hello_world_bytes = b"Hello World";
    label_ref[..hello_world_bytes.len()].copy_from_slice(hello_world_bytes);
    let nonce: [u8; 32] = rng.gen(); // Random nonce for the ephemeral resource
    Resource::create(
        HelloWorldLogic::verifying_key_as_bytes(),
        label_ref.to_vec(),
        1,
        convert_hello_world_to_value_ref(0u128), // Initialize with value/hello_world 0
        true,
        nonce.to_vec(),
        nf_key_cm,
    )
}

// This function initializes a hello_world resource from an ephemeral hello_world
// resource and its nullifier key. It sets the resource as non-ephemeral, renews
// its randomness, resets the nonce from the ephemeral hello_world, and sets the
// value reference to 1 (the initial hello_world value). It also renews the
// nullifier key(commitment) for the hello_world resource.
pub fn generate_persistent_hello_world_resource(
    consumed_hello_world: &Resource,
    ephemeral_hello_world_nf_key: &NullifierKey,
    nf_key_cm: &NullifierKeyCommitment,
) -> Resource {
    let mut init_hello_world = consumed_hello_world.clone();
    init_hello_world.is_ephemeral = false;
    init_hello_world.reset_randomness();
    init_hello_world.set_nonce_from_nf(consumed_hello_world, ephemeral_hello_world_nf_key);
    init_hello_world.set_value_ref(convert_hello_world_to_value_ref(1u128));
    init_hello_world.set_nf_commitment(nf_key_cm.clone());
    init_hello_world
}

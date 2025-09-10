use arm::logic_proof::LogicProver;
use arm::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use arm::resource::Resource;
use hello_world_library::HelloWorldLogic;
use rand::Rng;
use crate::util::{convert_hello_world_to_value_ref, convert_text_to_label_ref};

pub fn generate_ephemeral_hello_world_resource(nf_key_cm: NullifierKeyCommitment) -> Resource {
    let label_ref = convert_text_to_label_ref("");
    let value_ref = convert_hello_world_to_value_ref(0u128);
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen();
    Resource::create(
        HelloWorldLogic::verifying_key_as_bytes(),
        label_ref,
        1,
        value_ref,
        true,
        nonce.to_vec(),
        nf_key_cm,
    )
}

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

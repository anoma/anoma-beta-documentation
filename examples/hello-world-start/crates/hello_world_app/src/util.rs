use arm::action_tree::MerkleTree;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::logic_proof::{LogicProver, LogicVerifier};
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use hello_world_library::HelloWorldLogic;

pub fn generate_compliance_proof(
    consumed_hello_world: Resource,
    nf_key: NullifierKey,
    merkle_path: MerklePath,
    created_hello_world: Resource,
) -> (ComplianceUnit, Vec<u8>) {
    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_hello_world,
        nf_key,
        merkle_path,
        created_hello_world,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness);
    (compliance_unit, compliance_witness.rcv)
}

pub fn generate_logic_proofs(
    consumed_hello_world: Resource,
    nf_key: NullifierKey,
    created_hello_world: Resource,
) -> Vec<LogicVerifier> {
    let consumed_hello_world_nf = consumed_hello_world.nullifier(&nf_key).unwrap();
    let created_hello_world_cm = created_hello_world.commitment();

    let action_tree = MerkleTree::new(vec![consumed_hello_world_nf, created_hello_world_cm]);

    let consumed_hello_world_path = action_tree.generate_path(&consumed_hello_world_nf).unwrap();

    let consumed_hello_world_logic = HelloWorldLogic::new(
        true,
        consumed_hello_world.clone(),
        consumed_hello_world_path.clone(),
        nf_key.clone()
    );
    let consumed_logic_proof = consumed_hello_world_logic.prove();

    let created_hello_world_path = action_tree.generate_path(&created_hello_world_cm).unwrap();
    let created_hello_world_logic = HelloWorldLogic::new(
        false,
        created_hello_world,
        created_hello_world_path,
        nf_key,
    );
    let created_logic_proof = created_hello_world_logic.prove();

    vec![consumed_logic_proof, created_logic_proof]
}

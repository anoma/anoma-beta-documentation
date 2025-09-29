use arm::logic_proof::LogicProver;
use arm::{
    merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use hello_world_witness::HelloWorldWitness;
use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

pub const HELLO_WORLD_ELF: &[u8] = include_bytes!("../elf/hello_world_guest.bin");
lazy_static! {
    pub static ref HELLO_WORLD_ID: Digest =
        Digest::from_hex("d1dc300a67141213bd29c2cacc550aa37fa3cd062e59a977facc8826e01cfcce")
            .unwrap();
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct HelloWorldLogic {
    witness: HelloWorldWitness,
}

impl HelloWorldLogic {
    pub fn new(
        is_consumed: bool,
        hello_world: Resource,
        hello_world_existence_path: MerklePath,
        nf_key: NullifierKey,
    ) -> Self {
        Self {
            witness: HelloWorldWitness::new(
                is_consumed,
                hello_world,
                hello_world_existence_path,
                nf_key,
            ),
        }
    }
}

impl LogicProver for HelloWorldLogic {
    type Witness = HelloWorldWitness;
    fn proving_key() -> &'static [u8] {
        HELLO_WORLD_ELF
    }

    fn verifying_key() -> Digest {
        *HELLO_WORLD_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

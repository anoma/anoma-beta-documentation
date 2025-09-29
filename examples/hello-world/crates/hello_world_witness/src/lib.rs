pub use arm::resource_logic::LogicCircuit;
use arm::{
    logic_instance::{AppData, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct HelloWorldWitness {
    pub is_consumed: bool,
    pub hello_world: Resource,
    pub hello_world_existence_path: MerklePath,
    pub nf_key: NullifierKey,
}

impl HelloWorldWitness {
    pub fn new(
        is_consumed: bool,
        hello_world: Resource,
        hello_world_existence_path: MerklePath,
        nf_key: NullifierKey,
    ) -> Self {
        Self {
            is_consumed,
            hello_world,
            hello_world_existence_path,
            nf_key,
        }
    }
}

impl LogicCircuit for HelloWorldWitness {
    fn constrain(&self) -> LogicInstance {
        // Extract and validate label_ref from both resources
        let label: [u8; 11] = self.hello_world.label_ref[0..11].try_into().unwrap();
        
        // Verify that the label contains "Hello World"
        let expected_label = b"Hello World";
        assert_eq!(&label, expected_label);

        let tag = self.hello_world.tag(self.is_consumed, &self.nf_key);

        LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.is_consumed,
            root: self.hello_world_existence_path.root(&tag),
            app_data: AppData {..Default::default()},
        }
    }
}

# Hello World

This repository contains a simple example of an Anoma application demonstrating the basic concepts of resource creation, transaction construction, and zero-knowledge proof generation. It should be used as the starting point for following [Anoma's Hello World tutorial](https://docs.anoma.net/build/your-first-anoma-application). Thus, proofs will not work unless following the tutorial.

## Overview

The Hello World application showcases how to:
- Create ephemeral and persistent resources on the Anoma platform
- Generate compliance proofs for resource consumption and creation
- Build zero-knowledge logic proofs using RISC0
- Construct and verify transactions

## Running the Application

To run the hello world example:

```shell
cargo run --bin hello_world_app
```

This will execute the main transaction flow and output verification results.

## Building

The project uses Rust and requires the RISC0 toolchain for zero-knowledge proof generation. Build all components with:

```shell
cargo build
```

## Architecture

The project is organized into several crates:

- `hello_world_app`: Main application that creates transactions and demonstrates the flow
- `hello_world_library`: Contains the logic circuit implementation and proof generation
- `hello_world_witness`: Defines the witness structure for zero-knowledge proofs

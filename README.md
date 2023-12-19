# rdf-proofs-wasm

**WORK IN PROGRESS**

This library provides a thin wrapper for converting [zkp-ld/rdf-proofs](https://github.com/zkp-ld/rdf-proofs) to WebAssembly (WASM), enabling its use in TypeScript and JavaScript environments.

**⚠️ Experimental Phase**: Please note that this library is still experimental and not recommended for production use.

## Using the Library

If you simply want to use the library without building it from source, make sure you have Node.js and npm installed.
Then, you can install the library using npm:

```shell
npm install @zkp-ld/rdf-proofs-wasm
```

This command will add the `rdf-proofs-wasm` package to your project, allowing you to use it in your JavaScript or TypeScript applications.

## Usage

TBD

## Prerequisites for Development

Ensure you have the following installed:

- Node.js
- npm
- Rust
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (required for building WASM modules)

## How to Build

Follow these steps to build the library:

```shell
# Install wasm-pack if you haven't already
cargo install wasm-pack

# Clone the repository
git clone https://github.com/zkp-ld/rdf-proofs-wasm.git
cd rdf-proofs-wasm

# Install dependencies
npm install

# Build the project
npm run build
```

After building, the `lib` directory will contain the generated JavaScript/TypeScript files.

## Troubleshooting

### Error E0107

If you encounter the error E0107 after running `npm run build`, follow these steps:

1. Run `cargo clean` to clear the build cache.
1. Run `npm run build` again.

This can resolve issues caused by an inconsistent build from rust-analyzer in editors like VSCode.

```
error[E0107]: struct takes 3 generic arguments but 2 generic arguments were supplied
  --> /usr/local/cargo/registry/src/index.crates.io-6f17d22bba15001f/wasmparser-0.95.0/src/validator/component.rs:67:18
   |
67 |     pub imports: IndexMap<KebabString, (Option<Url>, ComponentEntityType)>,
   |                  ^^^^^^^^ -----------  ---------------------------------- supplied 2 generic arguments
   |                  |
   |                  expected 3 generic arguments
   |
```

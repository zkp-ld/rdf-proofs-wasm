#!/usr/bin/env bash

set -e

BUILD_MODE=$1

SRC_WASM=lib/rdf_proofs_wasm.js
NAME_WASM_BG=rdf_proofs_wasm_bg

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

if [ -z "$BUILD_MODE" ]
then
  echo "BUILD_MODE not specified defaulting to RELEASE"
  BUILD_MODE="RELEASE"
fi

# Build based on input parameter
if [ "$BUILD_MODE" = "RELEASE" ]; 
then
    echo "Building WASM Output in RELEASE MODE"
    wasm-pack build --release --out-dir lib --target web
elif [ "$BUILD_MODE" = "PROFILING" ];
then
    echo "Building WASM Output in PROFILING MODE"
    wasm-pack build --profiling --out-dir lib --target web
elif [ "$BUILD_MODE" = "DEBUG" ]; 
then
    echo "Building WASM Output in DEBUG MODE"
    wasm-pack build --dev --out-dir lib --target web -- --features="console"
else
    echo "Unrecognized value for parameter BUILD_MODE value must be either RELEASE or DEBUG"
    exit 1
fi

# Delete the un-necessary files automatically created by wasm-pack
rm lib/package.json lib/.gitignore lib/LICENSE lib/README.md

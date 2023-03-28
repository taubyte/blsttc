#/bin/bash

cargo wasi build --release

cp $(echo target/wasm32-wasi/release/*.wasi.wasm | head -1) artifact.wasm
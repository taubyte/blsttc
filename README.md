# blsttc
BLSTTC is a WASM bridge between the the Lit Protocol implementation of BLSTTC and the Taubyte VM.

## Building WASM 

### Requirements 
Install rustup
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install wasm32-wasi
```
rustup target add wasm32-wasi
```

### Build 

```
cd <clone-dir>/blsttc
./build.sh
```

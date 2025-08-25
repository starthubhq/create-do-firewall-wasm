cargo +nightly component build --release

sudo echo '{"params":{"do_token":"<access token>","name":"starthub-fw"}}' | DO_TOKEN=<access token> wasmtime -S http ./target/wasm32-wasip1/release/http-client.wasm

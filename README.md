# asr-unity-mono-mac-testing

Exploring how an ASR Unity / Mono library might try to support
Mac, and attempting to test potential library code.

This repository has branches to test it with 2 games so far:
 - Hollow Knight on the branch [hollowknight](https://github.com/AlexKnauth/asr-unity-mono-mac-testing/tree/hollowknight)
 - Superliminal on the branch [superliminal](https://github.com/AlexKnauth/asr-unity-mono-mac-testing/tree/superliminal)

## Compilation

This auto splitter is written in Rust. In order to compile it, you need to
install the Rust compiler: [Install Rust](https://www.rust-lang.org/tools/install).

Afterwards install the WebAssembly target:
```sh
rustup target add wasm32-wasi --toolchain stable
```

The auto splitter can now be compiled:
```sh
cargo b
```

The auto splitter is then available at:
```
target/wasm32-wasi/release/asr_unity_mono_mac_testing.wasm
```

Make sure too look into the [API documentation](https://livesplit.org/asr/asr/) for the `asr` crate.

You can use the [debugger](https://github.com/CryZe/asr-debugger) while
developing the auto splitter to more easily see the log messages, statistics,
dump memory and more.

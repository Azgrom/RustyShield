This library is built exclusively on top of `core-crate`, excepting the binary deployment and integrate test that require the `std-crate` to interact with file-system files/streams. If you are using this crate only as a library, it will not require anything other than the `core-crate`.

Cargo requires specification of what exactly you want to compile. If you simply run `cargo build`, currently cargo will build the library alongside with the executable binary.

So for compiling only the library you should run `cargo build --lib`. 

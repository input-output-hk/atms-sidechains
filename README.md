# Ad-hoc Threshold Multi-Signatures ![CI workflow](https://github.com/github/input-output-hk/atms-sidechains/actions/workflows/ci.yml/badge.svg) ![crates.io](https://img.shields.io/crates/v/atms.svg)

Proof of Concept implementation. 
This crate is ongoing work, has not been audited, and API is by no means final. 
Do not use.

## A Rust implementation of ATMS signatures
`atms` implements Ad-Hoc Threshold MultiSignatures (ATMS) implementation using
[Boldyreva](https://link.springer.com/chapter/10.1007%2F3-540-36288-6_3)
multi signature scheme as described in Section 5.2 of the
[Proof-of-Stake Sidechains](https://cointhinktank.com/upload/Proof-of-Stake%20Sidechains.pdf)
by Gazi, Kiayias and Zindros. Elliptic curve cryptography, and basic
signature procedures are performed using the [`blst`](https://github.com/supranational/blst)
library by supranational which implements BLS signatures over curve
BLS12-381.

The library exposes a C API for facilitating its usage with other languages. 

# ATMS C library Usage

## Environment

Compiling and testing the C library requires a working installation of [clang](https://clang.llvm.org/) and [gtest](https://github.com/google/googletest).
To do so, one can check the documentation of your package-manager for system-dependent install instructions.

Note: For MacOS I made it work by adding `-std=c++<VERSION>` to the `clang` command below, after installing `gtest` as
specified [here](https://github.com/google/googletest/blob/main/googletest/README.md#standalone-cmake-project).
`<VERSION>` needs to be 11 or higher.

## Compiling the library and header file
First, one needs to compile the library running:
```shell
cargo build --release
```

Then, we need to build the header files using `cbindgen`. For this, first install
cbindgen:
```shell
cargo install cbindgen
```

and then build the header file by running the following command from the parent directory (nightly is required):
```shell
rustup run nightly cbindgen ./ --config cbindgen.toml --crate atms --output target/include/atms.h
```

## Running tests

For running rust tests, simply run (recommended use of `--release`, otherwise it takes a while):

```shell
cargo test --release
```

For the c-tests, we first build the test executable. First enter the `c-tests` folder, and then run:

``` sh
clang -x c++ tests.c stms.c atms.c -g -o tests -L ../target/release -lmithril -lstdc++ -lgtest -lgtest_main
```

**NOTE**: Do not use g++, it does compile but leads to segfault when running the test.

To execute the tests:

``` sh
./tests
[==========] Running 5 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 3 tests from atms
[ RUN      ] atms.produceAndVerifyAggregateSignature
[       OK ] atms.produceAndVerifyAggregateSignature (27 ms)
[ RUN      ] atms.testingErrors
[       OK ] atms.testingErrors (29 ms)
[ RUN      ] atms.serdeAtms
[       OK ] atms.serdeAtms (14 ms)
[----------] 3 tests from atms (71 ms total)

[----------] 2 tests from multisig
[ RUN      ] multisig.produceAndVerifyMultiSignature
[       OK ] multisig.produceAndVerifyMultiSignature (2 ms)
[ RUN      ] multisig.serdeMultiSignature
[       OK ] multisig.serdeMultiSignature (2 ms)
[----------] 2 tests from multisig (4 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 2 test suites ran. (76 ms total)
[  PASSED  ] 5 tests.
```

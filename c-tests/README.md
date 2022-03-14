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

and then build the header file by running the following command from the parent directory:
```shell
rustup run nightly cbindgen ./ --config cbindgen.toml --crate atms --output target/include/atms.h
```

## Running tests

Now we can build the test executable. First enter the `c-tests` folder, and then run:

``` sh
clang -x c++ tests.c stms.c atms.c -g -o tests -L ../target/release -lmithril -lstdc++ -lgtest -lgtest_main
```

**NOTE**: Do not use g++, it does compile but leads to segfault when running the test.

To execute the tests:

``` sh
./tests
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from atm
[ RUN      ] atm.produceAndVerifyAggregateSignature
[       OK ] atm.produceAndVerifyAggregateSignature (17 ms)
[ RUN      ] atm.testingErrors
[       OK ] atm.testingErrors (20 ms)
[----------] 2 tests from atm (38 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (38 ms total)
[  PASSED  ] 2 tests.
```

# BIP-39 Mnemonic Generator

> [!CAUTION]
> This is an educational project. It has not been independently audited and should not be trusted to protect real funds.
>
> Mnemonics, entropy, screenshots, terminal scrollback, shell recordings, logs, and backups may expose wallet recovery material. Any mnemonic or entropy displayed on a networked or untrusted computer should be considered compromised.
>
> The optional `--show-entropy` output reveals secret material equivalent to the mnemonic. Use it only for testing and study.
>
> This program implements the mnemonic-generation portion of BIP-39. It does not convert a mnemonic and optional passphrase into the 512-bit binary seed used by BIP-32 wallets.

A C++20 command-line program that generates BIP-39 mnemonic sentences.

The program:

1. Obtains cryptographically secure entropy from OpenSSL.
2. Computes the BIP-39 SHA-256 checksum.
3. Appends the required checksum bits to the entropy.
4. Divides the resulting bit sequence into 11-bit indices.
5. Looks up those indices in a user-provided 2,048-word list.
6. Prints the mnemonic and a binary representation of each word index.

The binary index output is labeled **Tiny Seed**. It is intended as a compact representation that may be transferred to a physical medium such as stamped metal.

## Features

* Generates valid BIP-39 mnemonic lengths:

  * 12 words from 128 bits of entropy
  * 15 words from 160 bits of entropy
  * 18 words from 192 bits of entropy
  * 21 words from 224 bits of entropy
  * 24 words from 256 bits of entropy
* Uses OpenSSL `RAND_priv_bytes()` for cryptographically secure entropy.
* Uses OpenSSL SHA-256 for the BIP-39 checksum.
* Derives zero-based 11-bit wordlist indices as specified by BIP-39.
* Accepts a user-provided wordlist file.
* Requires exactly 2,048 non-empty, unique wordlist entries.
* Allows repeated words when produced by the entropy.
* Optionally displays the original entropy and checksum for educational inspection.
* Prints each word index as an 11-bit Tiny Seed pattern.
* Builds as a C++20 program using CMake.

## BIP-39 Scope

BIP-39 consists of two main operations:

1. Converting entropy into a mnemonic sentence.
2. Converting the mnemonic and an optional passphrase into a 512-bit binary seed using PBKDF2-HMAC-SHA512.

This project currently implements the first operation only.

The mnemonic is generated using:

```text
CS = ENT / 32
MS = (ENT + CS) / 11
```

Where:

* `ENT` is the original entropy length in bits.
* `CS` is the checksum length in bits.
* `MS` is the number of mnemonic words.

The first `CS` bits of the SHA-256 digest of the entropy are appended to the entropy. The combined sequence is divided into 11-bit groups, and each group is used as a zero-based index from `0` through `2047`.

The included BIP submodule contains the [BIP-39 specification](external/bips/bip-0039.mediawiki).

## Requirements

* A C++20-compatible compiler

  * Apple Clang
  * Clang
  * GCC
  * Another compiler with adequate C++20 support
* CMake 3.20 or newer
* OpenSSL Crypto
* A 2,048-entry wordlist

### macOS

The provided macOS build script expects:

* Homebrew
* OpenSSL 3 installed through Homebrew
* Apple Clang or another C++20 compiler available to CMake

Install the dependencies with:

```sh
brew install cmake openssl@3
```

### Debian and Ubuntu

Install the usual development packages with:

```sh
sudo apt install build-essential cmake libssl-dev
```

## Clone the Repository

Clone the main repository:

```sh
git clone https://github.com/Fudmottin/bip39.git
cd bip39
```

To also initialize the BIP specification and wordlist submodule:

```sh
git submodule update --init --recursive
```

Alternatively, clone everything at once:

```sh
git clone --recurse-submodules https://github.com/Fudmottin/bip39.git
cd bip39
```

## Build Instructions

### macOS Build Script

The repository includes `macos-build.sh`, which configures a Release build and supplies the Homebrew OpenSSL location to CMake:

```sh
sh macos-build.sh
```

Example output:

```text
$ sh macos-build.sh 
-- The CXX compiler identification is AppleClang 21.0.0.21000101
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found OpenSSL: /opt/homebrew/opt/openssl@3/lib/libcrypto.dylib (found version "3.6.3") found components: Crypto
-- Configuring done (0.2s)
-- Generating done (0.0s)
-- Build files have been written to: /Users/user/Projects/cpp/bip39/build
[ 50%] Building CXX object CMakeFiles/seeds.dir/src/seeds.cpp.o
[100%] Linking CXX executable seeds
[100%] Built target seeds
```

The executable is created at:

```text
build/seeds
```

### Manual macOS Build

Configure the project using Homebrew OpenSSL:

```sh
cmake \
   -S . \
   -B build \
   -DCMAKE_BUILD_TYPE=Release \
   -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

Build it:

```sh
cmake --build build
```

### General Build

On a system where CMake can locate OpenSSL without an explicit path:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

For a Debug build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Run the Program

The command syntax is:

```sh
./build/seeds <wordlist-file> <word-count> [--show-entropy]
```

Arguments:

* `<wordlist-file>` is the path to a 2,048-entry wordlist.
* `<word-count>` must be `12`, `15`, `18`, `21`, or `24`.
* `--show-entropy` optionally displays the source entropy and checksum bits.

Generate a 12-word mnemonic:

```sh
./build/seeds english-seeds.txt 12
```

Generate a 24-word mnemonic:

```sh
./build/seeds english-seeds.txt 24
```

Display the entropy and checksum for inspection:

```sh
./build/seeds english-seeds.txt 24 --show-entropy
```

The program reports the random-number API path without displaying the random bytes unless `--show-entropy` is selected:

```text
Entropy path: OpenSSL RAND_priv_bytes() <- OpenSSL private CSPRNG <- operating-system random generator
```

## Output

The normal output contains two sections.

### Seed Words

This section displays the mnemonic words in their original order.

```text
    Seed Words

     1) document
     2) exit
     3) donate
```

### Tiny Seed

This section displays the exact zero-based 11-bit index of each word.

```text
    Tiny Seed

     1) _ █ _ _ _ _ _ _ _ █ █
     2) _ █ _ _ █ █ █ █ █ █ █
     3) _ █ _ _ _ _ _ █ _ _ _
```

An underscore represents zero and a solid block represents one.

The indices are zero-based:

```text
wordlist[0]    = 00000000000
wordlist[2047] = 11111111111
```

Do not add one to an index before recording or stamping it. A one-based value represents a different word and cannot represent all 2,048 entries in 11 bits.

### Entropy Diagnostics

When `--show-entropy` is supplied, an additional section is displayed:

```text
    BIP-39 Internals

Entropy:      7dd0aec8b6d75998d27f675baa27cf46475d2a8980dcd6cb3faa1fb5d081d872
Checksum:     01010101
Entropy bits: 256
Checksum bits: 8
```

This information is useful for:

* comparing output with BIP-39 test vectors;
* verifying the SHA-256 checksum;
* reconstructing the 11-bit word indices;
* studying the mnemonic-generation process.

The displayed entropy must be protected as carefully as the mnemonic itself.

## Wordlist Files

The included `english-seeds.txt` file contains the official 2,048-word BIP-39 English wordlist.

The program also accepts another wordlist file:

```sh
./build/seeds path/to/wordlist.txt 24
```

A wordlist must contain:

* exactly 2,048 lines;
* one word per line;
* no empty lines;
* no duplicate words.

The exact order is significant. Each position corresponds to a particular 11-bit index.

A custom wordlist preserves the underlying BIP-39 index construction, but it will not be interoperable with standard wallets unless those wallets use the identical words in the identical order.

BIP-39 requires non-ASCII wordlists to use UTF-8 NFKD normalization. This program does not perform Unicode normalization. The included English list is ASCII and is unaffected by this limitation.

Additional standard wordlists are available in the initialized submodule under:

```text
external/bips/bip-0039/
```

## Randomness and Security

Entropy is generated with:

```cpp
RAND_priv_bytes()
```

The program requests only the entropy bytes required for the selected mnemonic length:

| Words |  Entropy | Checksum |
| ----: | -------: | -------: |
|    12 | 128 bits |   4 bits |
|    15 | 160 bits |   5 bits |
|    18 | 192 bits |   6 bits |
|    21 | 224 bits |   7 bits |
|    24 | 256 bits |   8 bits |

OpenSSL maintains a cryptographically secure pseudorandom-number generator and seeds it from the operating system’s randomness facilities.

The program does not:

* use `std::mt19937`;
* use `std::random_device`;
* scan or hash ordinary files;
* read `/dev/random` directly;
* substitute a weaker source if OpenSSL fails.

Failure to obtain secure entropy causes the program to terminate with an error.

OpenSSL deliberately abstracts the operating system’s internal entropy collection. The program can report that OpenSSL requested entropy from the operating system, but it cannot determine whether the operating system internally incorporated a hardware random-number generator or any particular physical entropy source.

## Security Considerations

This project is intended to explain and demonstrate BIP-39 mnemonic generation.

Before considering similar software for real wallet recovery material, at minimum:

* review and test the implementation independently;
* compare it against official BIP-39 test vectors;
* build it from reviewed source;
* use a trusted and preferably offline computer;
* prevent terminal output from being logged or retained;
* verify the supplied wordlist and its ordering;
* securely erase any temporary output where practical;
* understand that displaying entropy or mnemonic words exposes wallet recovery material.

No warranty is made that this software is suitable for securing funds.

## License

This project is licensed under the GNU General Public License version 3. See [LICENSE](LICENSE) for details.


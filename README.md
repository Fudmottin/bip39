# BIP-39 Mnemonic Generator

> [!CAUTION]
> This is an educational project. It has not been independently audited and should not be trusted to protect real funds.
>
> A mnemonic and its source entropy are secret wallet recovery material. Terminal output, scrollback, screenshots, shell recordings, logs, redirected output, and backups may retain them.
>
> Generate real wallet material only on a trusted and preferably offline computer. The `--show-entropy` option deliberately exposes the entropy and should be used only for testing and study.

A C++20 command-line utility that generates BIP-39 mnemonic sentences.

With no arguments, the program generates a 12-word mnemonic using:

* the compiled-in official English BIP-39 wordlist;
* entropy from OpenSSL `RAND_priv_bytes()`;
* SHA-256 for the BIP-39 checksum.

Optional command-line arguments select another mnemonic length, load another wordlist, display diagnostic information, or interactively mix physical dice rolls with OpenSSL randomness.

## Scope

BIP-39 has two main operations:

1. Convert initial entropy into a mnemonic sentence.
2. Convert the mnemonic and an optional passphrase into a 512-bit binary seed using PBKDF2-HMAC-SHA512.

This project implements the first operation only. It does not derive the 512-bit seed used by BIP-32 wallets.

The mnemonic calculation is:

```text
CS = ENT / 32
MS = (ENT + CS) / 11
```

Where:

* `ENT` is the initial entropy length in bits.
* `CS` is the checksum length in bits.
* `MS` is the mnemonic word count.

The first `CS` bits of `SHA-256(entropy)` are appended to the entropy. The resulting bit sequence is divided into 11-bit groups, each of which selects one entry from a 2,048-word list.

The official specification is available from the [Bitcoin BIPs repository](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). It is also available in the optional repository submodule at `external/bips/bip-0039.mediawiki`.

## Features

* Generates valid BIP-39 mnemonic lengths:

  * 12 words from 128 bits of entropy
  * 15 words from 160 bits of entropy
  * 18 words from 192 bits of entropy
  * 21 words from 224 bits of entropy
  * 24 words from 256 bits of entropy
* Uses the official English wordlist compiled into the executable by default.
* Optionally loads a 2,048-entry wordlist from a file.
* Uses OpenSSL `RAND_priv_bytes()` for cryptographically secure system entropy.
* Provides an interactive dice mode that combines physical rolls with OpenSSL randomness.
* Uses OpenSSL SHA-256 for entropy conditioning and the BIP-39 checksum.
* Validates command-line options with Boost.Program_options.
* Optionally displays the entropy and checksum for educational inspection.
* Prints every mnemonic word and its zero-based 11-bit wordlist index.
* Builds as a C++20 program with CMake.

## Requirements

* A C++20-compatible compiler
* CMake 3.20 or newer
* OpenSSL Crypto
* Boost 1.90 or newer with Program_options

The project has been developed with Apple Clang on macOS. It should also build with sufficiently recent Clang or GCC installations.

## Clone the Repository

The BIP submodule is optional. The program does not require it because the English wordlist is compiled into the executable.

```sh
git clone https://github.com/Fudmottin/bip39.git
cd bip39
```

To also obtain the BIP specifications and standard wordlists:

```sh
git submodule update --init --recursive
```

Alternatively:

```sh
git clone --recurse-submodules https://github.com/Fudmottin/bip39.git
cd bip39
```

## Build

### macOS with Homebrew

Install the dependencies:

```sh
brew install cmake boost openssl@3
```

The provided script configures and builds a Release executable:

```sh
./macos-build.sh
```

The executable is created at:

```text
build/seeds
```

The equivalent manual commands are:

```sh
cmake \
   -S . \
   -B build \
   -DCMAKE_BUILD_TYPE=Release \
   -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake --build build
```

### Debian and Ubuntu

The usual package names are:

```sh
sudo apt install \
   build-essential \
   cmake \
   libssl-dev \
   libboost-program-options-dev
```

The installed Boost package must provide Boost 1.90 or newer. Older distribution releases may require a newer Boost installation from another source.

Configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Debug Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Usage

```text
seeds [options]
```

Options:

| Short      | Long              | Meaning                                              |
| ---------- | ----------------- | ---------------------------------------------------- |
| `-h`       | `--help`          | Display help and exit                                |
| `-w FILE`  | `--wordlist FILE` | Load a 2,048-entry wordlist from `FILE`              |
| `-n COUNT` | `--words COUNT`   | Generate 12, 15, 18, 21, or 24 words                 |
| `-d`       | `--dice`          | Interactively mix dice rolls with OpenSSL randomness |
| `-e`       | `--show-entropy`  | Display the entropy and BIP-39 checksum              |

Defaults:

```text
Wordlist:   compiled English BIP-39 wordlist
Words:      12
Dice mode:  disabled
Diagnostics: disabled
```

No positional arguments are required or accepted.

### Default 12-word mnemonic

```sh
./build/seeds
```

### Select another mnemonic length

```sh
./build/seeds --words 24
```

Short form:

```sh
./build/seeds -n 24
```

Valid word counts are:

```text
12 15 18 21 24
```

### Use an external wordlist

```sh
./build/seeds --wordlist english-seeds.txt
```

Select both a wordlist and mnemonic length:

```sh
./build/seeds \
   --wordlist path/to/wordlist.txt \
   --words 24
```

### Display entropy diagnostics

```sh
./build/seeds --show-entropy
```

This displays secret material equivalent to the mnemonic. It should not be used casually.

### Display help

```sh
./build/seeds --help
```

## Entropy Sources

### System Entropy

Without `--dice`, the required entropy bytes are obtained directly from:

```cpp
RAND_priv_bytes()
```

The program reports the entropy path without displaying the random bytes:

```text
Entropy path: OpenSSL RAND_priv_bytes() <- OpenSSL private CSPRNG <- operating-system random generator
```

The program does not:

* use `std::mt19937`;
* use `std::random_device`;
* scan or hash ordinary files;
* open `/dev/random` directly;
* substitute a weaker source if OpenSSL fails.

Failure to obtain secure randomness causes the program to terminate with an error.

OpenSSL abstracts the operating system's entropy collection. The program cannot determine whether the operating system internally used a hardware random-number generator or another particular physical source.

### Interactive Dice Mode

Enable dice mode with:

```sh
./build/seeds --dice
```

The program announces the required number of rolls and prompts for each result:

```text
Entropy path: SHA-256(dice rolls || RAND_priv_bytes())
Dice mode requires 75 rolls for 128 bits of BIP-39 entropy.
Enter each die result as a number from 1 through 6.

Roll 1/75:
```

Enter one result from `1` through `6` at each prompt. Invalid input does not consume the roll; the same roll number is requested again.

The number of rolls depends on the selected mnemonic length:

| Words | BIP-39 entropy | Dice rolls |
| ----: | -------------: | ---------: |
|    12 |       128 bits |         75 |
|    15 |       160 bits |         87 |
|    18 |       192 bits |        100 |
|    21 |       224 bits |        112 |
|    24 |       256 bits |        124 |

Assuming independent fair rolls, these counts provide approximately 64 more bits of nominal dice entropy than the requested BIP-39 entropy length.

Dice mode constructs the input:

```text
"bip39-dice-v1"
|| entropy-bit-count
|| roll-count
|| encoded-dice-rolls
|| 32 bytes from RAND_priv_bytes()
```

The entropy-bit count and roll count are encoded as unsigned 16-bit big-endian values. Die faces `1` through `6` are encoded as values `0` through `5`.

SHA-256 conditions the combined input:

```text
SHA-256(
   domain separator
   || entropy length
   || roll count
   || dice rolls
   || OpenSSL private randomness
)
```

The digest is truncated to the required BIP-39 entropy length. A 24-word mnemonic uses the complete 32-byte digest.

The resulting entropy then follows the same BIP-39 checksum and word-selection path as system-generated entropy.

Important consequences:

* Dice mode always combines the rolls with OpenSSL randomness.
* There is currently no dice-only mode.
* The result cannot be reproduced later from the dice rolls alone.
* Hashing conditions entropy but does not create entropy absent from its inputs.
* Dice entries are echoed by the terminal and may remain in scrollback or recordings.
* A compromised executable or operating system can still expose or replace the result.

Example for a 24-word mnemonic:

```sh
./build/seeds --dice --words 24
```

Dice mode may also be combined with an external wordlist or diagnostics:

```sh
./build/seeds \
   --dice \
   --words 24 \
   --wordlist path/to/wordlist.txt \
   --show-entropy
```

## Wordlists

The official English BIP-39 wordlist is compiled into the executable and is used when `--wordlist` is absent.

The repository also contains `english-seeds.txt`, which may be loaded explicitly for comparison:

```sh
./build/seeds --wordlist english-seeds.txt
```

An external wordlist must contain:

* exactly 2,048 lines;
* one word per line;
* no empty lines;
* no duplicate words.

Both the words and their exact order are significant. Every position corresponds to one zero-based 11-bit index.

A custom wordlist preserves the underlying index construction, but it will not interoperate with ordinary BIP-39 wallets unless they use the identical words in the identical order.

BIP-39 requires non-ASCII wordlists to use UTF-8 NFKD normalization. This program does not perform Unicode normalization. The compiled English wordlist is ASCII and is unaffected by this limitation.

Additional standard wordlists are available after initializing the submodule:

```text
external/bips/bip-0039/
```

## Output

Normal output contains two sections.

### Seed Words

The mnemonic words are printed in their original order:

```text
    Seed Words

     1) document
     2) exit
     3) donate
```

### Tiny Seed

Tiny Seed is this program's label for the zero-based 11-bit index of each mnemonic word:

```text
    Tiny Seed

     1) _ █ _ _ _ _ _ _ _ █ █
     2) _ █ _ _ █ █ █ █ █ █ █
     3) _ █ _ _ _ _ _ █ _ _ _
```

An underscore represents zero. A solid block represents one.

The indices are zero-based:

```text
wordlist[0]    = 00000000000
wordlist[2047] = 11111111111
```

Do not add one to an index before recording or stamping it. A one-based value identifies a different word and cannot represent all 2,048 entries in 11 bits.

Tiny Seed is a physical representation of the same recovery secret as the mnemonic. It must receive the same protection.

### Entropy Diagnostics

With `--show-entropy`, the program also displays:

```text
    BIP-39 Internals

Entropy:      7dd0aec8b6d75998d27f675baa27cf46475d2a8980dcd6cb3faa1fb5d081d872
Checksum:     01010101
Entropy bits: 256
Checksum bits: 8
```

This can be useful for:

* comparing output with BIP-39 test vectors;
* verifying the SHA-256 checksum;
* reconstructing the 11-bit indices;
* studying mnemonic generation.

The displayed entropy can recreate the mnemonic and must be protected just as carefully.

## Errors

Invalid command-line arguments, unsupported word counts, malformed wordlists, OpenSSL failures, and incomplete dice input cause the program to print an error and terminate with a nonzero exit status.

Examples of invalid invocations include:

```sh
./build/seeds --words 13
./build/seeds --words nonsense
./build/seeds --unknown
./build/seeds --wordlist
```

## Security Considerations

This project is intended to explain and demonstrate BIP-39 mnemonic generation.

Before considering similar software for real wallet recovery material:

* review and test the implementation independently;
* compare it against official BIP-39 test vectors;
* build it from reviewed source;
* use a trusted and preferably offline computer;
* prevent terminal output from being logged or retained;
* verify any external wordlist and its ordering;
* protect dice entries from observation;
* securely erase temporary output where practical;
* understand that entropy, mnemonic words, and Tiny Seed patterns represent equivalent recovery secrets.

Generating entropy safely does not protect it after generation. The operating system, terminal, display server, shell environment, copied text, storage, backups, and physical surroundings remain part of the trust boundary.

No warranty is made that this software is suitable for securing funds.

## License

This project is licensed under the GNU General Public License version 3. See [LICENSE](LICENSE) for details.


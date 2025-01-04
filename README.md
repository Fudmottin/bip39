# Seed Phrase Generator

This is a C++20 command-line tool for generating BIP-39-compatible seed phrases for cryptocurrency wallets.  
It uses high-quality random sources and supports customizable wordlist files.

## Features

- Generates customizable seed phrases (e.g., 12 or 24 words).
- Uses BIP-39-compatible wordlists (e.g., `english-seeds.txt`).
- Includes additional entropy from system files and hardware random sources.
- Compatible with macOS, Linux, and Windows.
- Builds with `CMake` with Debug and Release configurations.

## Requirements

- C++20 compatible compiler (GCC, Clang, or MSVC).
- `CMake` version 3.15 or higher.

## Setup and Build Instructions

### Clone the Repository

```bash
git clone https://github.com/Fudmottin/bip39
cd bip39
```

### Configure and Build

1. Create a build directory and configure the project:

    ```bash
    mkdir build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    ```

    Use `-DCMAKE_BUILD_TYPE=Debug` for debug builds.

2. Compile the project:

    ```bash
    make
    ```

    The executable will be available in the `build` directory.

### Run the Program

```bash
./seeds <wordlist-file> <number-of-words> [optional-password]
```

- `<wordlist-file>`: Path to the BIP-39 wordlist (e.g., `english-seeds.txt`).
- `<number-of-words>`: Number of words in the seed phrase (e.g., 12, 24).
- `[optional-password]`: Optional passphrase for added wallet security.

Example usage:

```bash
./seeds english-seeds.txt 12
./seeds english-seeds.txt 24 my_passphrase
```

## Wordlist Files

The `english-seeds.txt` file contains the official BIP-39 English wordlist (2048 words).  
For multilingual support, download and use additional BIP-39-compatible wordlists (e.g., Spanish, French).
You may find them at [bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039). Simply download
your preferred language file and use that.

### Adding Additional Wordlists

To use a different language, provide the corresponding wordlist file as the first argument:

```bash
./seeds spanish-seeds.txt 24
```

Ensure that the wordlist complies with BIP-39 to maintain compatibility with wallets.

## Randomness and Security

The tool uses:

- A secure random number generator (`std::mt19937` with high-entropy seeding).
- Entropy from system-accessible files.
- Hardware random sources (e.g., `/dev/random` on Unix-like systems).

This approach ensures strong randomness for wallet initialization.

## Licensing

This project is licensed under the **GNU General Public License (GPL) v3.0**. See the `LICENSE` file for details.


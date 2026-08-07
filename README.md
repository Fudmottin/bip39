BIP-39 Mnemonic Generator

[!CAUTION]This is an educational project. It has not been independently audited andshould not be trusted to protect real funds.

Mnemonics, entropy, BIP-39 seeds, and passphrases are secret wallet recoverymaterial. Terminal output, scrollback, screenshots, shell recordings, logs,redirected output, and backups may retain them.

Generate real wallet material only on a trusted and preferably offlinecomputer. Review the source, build it yourself, and verify the tests.

A C++20 command-line utility for generating BIP-39 mnemonic sentences andderiving their 64-byte BIP-39 seeds.

With no arguments, the program generates a 12-word mnemonic using the compiledofficial English wordlist and entropy from OpenSSL RAND_priv_bytes().

Scope

BIP-39 has two operations:

Convert initial entropy into a mnemonic sentence.

Convert the mnemonic and an optional passphrase into a 512-bit seed usingPBKDF2-HMAC-SHA512.

This project implements both operations. It does not implement BIP-32 keys,wallet derivation paths, addresses, transactions, or wallet storage.

Mnemonic generation uses:

CS = ENT / 32
MS = (ENT + CS) / 11

The first CS bits of SHA-256(entropy) are appended to the entropy. Thecombined bit sequence is split into 11-bit wordlist indices.

Seed derivation uses:

PBKDF2-HMAC-SHA512
password   = mnemonic
salt       = "mnemonic" + passphrase
iterations = 2048
output     = 64 bytes

BIP-39 requires UTF-8 NFKD normalization. This project currently accepts onlyASCII mnemonic and passphrase text for seed derivation.

See theBIP-39 specification.

Features

Generates 12, 15, 18, 21, or 24-word BIP-39 mnemonics.

Uses the compiled official English wordlist by default.

Optionally loads a 2,048-entry wordlist from a file.

Uses OpenSSL RAND_priv_bytes() for default entropy.

Supports mixed and reproducible dice entropy modes.

Supports mixed and reproducible shuffled-card entropy modes.

Derives and displays the BIP-39 seed on request.

Reads passphrases interactively with terminal echo disabled.

Displays entropy and checksum diagnostics on request.

Prints each mnemonic word and its zero-based 11-bit wordlist index.

Tests mnemonic, seed, dice, card, and validation behavior through CTest.

Requirements

A C++20-compatible compiler

CMake 3.20 or newer

OpenSSL Crypto

Boost 1.90 or newer with Program_options

POSIX terminal APIs for hidden passphrase entry

The current CLI is developed on macOS and uses termios, unistd, and POSIXsignals. Windows requires a separate terminal-input implementation.

Clone

git clone https://github.com/Fudmottin/bip39.git
cd bip39

The BIP submodule is optional. To initialize it:

git submodule update --init --recursive

Build

macOS with Homebrew

brew install cmake ninja boost openssl@3

Release build:

./macos-build.sh

The executable is created at:

build/seeds

Debug build with tests:

./macos-debug-build.sh

The Debug executables are:

build/debug/seeds
build/debug/tests/bip39_tests

Equivalent Debug commands:

cmake \
   -S . \
   -B build/debug \
   -G Ninja \
   -DCMAKE_BUILD_TYPE=Debug \
   -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake --build build/debug
ctest --test-dir build/debug --output-on-failure

Debian and Ubuntu

sudo apt install \
   build-essential \
   cmake \
   libssl-dev \
   libboost-program-options-dev

The installed Boost package must provide version 1.90 or newer.

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

Disable test targets with:

cmake -S . -B build -DBUILD_TESTING=OFF

Testing

Run CTest:

ctest --test-dir build/debug --output-on-failure

Run the test executable directly to see successful checks:

./build/debug/tests/bip39_tests

Expected summary:

24 BIP-39 English mnemonic and seed vectors passed
BIP-39 input validation passed
BIP-39 ASCII seed derivation passed
Dice entropy derivation passed
Card entropy derivation passed

The tests use fixed inputs. They never wait for physical dice, shuffled cards,system randomness, or a passphrase.

Usage

seeds [options]

Short

Long

Meaning

-h

--help

Display help and exit

-w FILE

--wordlist FILE

Load a 2,048-entry wordlist

-n COUNT

--words COUNT

Generate 12, 15, 18, 21, or 24 words

-d

--dice

Mix dice rolls with OpenSSL randomness



--dice-only

Hash ASCII dice rolls without system randomness



--cards

Mix one shuffled deck with OpenSSL randomness



--cards-only

Use shuffled deck orderings without system randomness

-e

--show-entropy

Display entropy and checksum



--show-seed

Prompt for a passphrase and display the BIP-39 seed

The four physical entropy-source options are mutually exclusive. With noneselected, the program uses OpenSSL system entropy.

Examples:

./build/seeds
./build/seeds --words 24
./build/seeds --show-entropy
./build/seeds --show-seed
./build/seeds --dice --words 24
./build/seeds --cards-only --words 21

No positional arguments are accepted.

Entropy Sources

Every entropy source first produces 16, 20, 24, 28, or 32 bytes. Those bytesthen use the same BIP-39 checksum and word-selection code.

System Entropy

The default mode obtains the required bytes directly from:

RAND_priv_bytes()

The program does not use std::mt19937, std::random_device, ordinary files,or /dev/random directly. Failure to obtain secure randomness terminates theprogram.

Mixed Dice: --dice

This mode combines physical rolls with 32 bytes from RAND_priv_bytes():

SHA-256(
   "bip39-dice-v1"
   || entropy-bit-count
   || roll-count
   || zero-based dice values
   || 32 OpenSSL random bytes
)

Words

Entropy

Rolls

12

128 bits

75

15

160 bits

87

18

192 bits

100

21

224 bits

112

24

256 bits

124

Enter one result from 1 through 6 at each prompt. Invalid input repeats thesame roll number. The result cannot be reproduced from the dice alone becauseOpenSSL randomness is included.

Dice-Only Compatibility: --dice-only

This mode hashes the exact ASCII roll characters:

SHA-256(ASCII dice rolls)

Words

Entropy

Rolls

12

128 bits

50

15

160 bits

62

18

192 bits

75

21

224 bits

87

24

256 bits

99

The 99-roll value is retained for compatibility with the documented COLDCARDand SeedSigner convention, although 99 fair rolls contain slightly less than256 bits of nominal entropy.

No system randomness is mixed into this mode. Its security depends entirely onthe privacy, independence, fairness, and correct entry of the rolls.

Mixed Cards: --cards

This mode reads one shuffled 52-card deck and combines it with 32 OpenSSL randombytes:

SHA-256(
   "bip39-cards-v1"
   || canonical deck ordering
   || 32 OpenSSL random bytes
)

Cards-Only: --cards-only

This mode uses:

one shuffled deck for 12, 15, 18, or 21 words;

two independently shuffled deck orderings for 24 words.

For 24 words, the program asks the user to restore the deck to canonical order,perform a fresh shuffle, and enter the second ordering. The two submittedorderings must differ.

No system randomness is mixed into cards-only mode.

Card Entry

Enter one card at a time from the top of the deck to the bottom:

Shuffle 1, card 1/52: as
Shuffle 1, card 2/52: 10d
Shuffle 1, card 3/52: qh

Ranks:

a 2 3 4 5 6 7 8 9 10 j q k

Suits:

c d h s

Examples:

as   ace of spades
10d  ten of diamonds
qh   queen of hearts

The letter t may replace 10, so td and 10d are equivalent. Input iscase-insensitive.

The parser normalizes each card to a two-character form and rejects invalid orduplicate cards. An error repeats the same card position.

The repository includes a parser smoke test:

./cards-parser-test.sh

It feeds an ordered, deliberately nonrandom deck to the Debug executable. It isonly a parser and control-flow test and must not be used to generate walletmaterial.

Seed Derivation: --show-seed

This option appends a BIP-39 derivation section after Tiny Seed.

The program prompts:

BIP-39 passphrase (empty for none):

An empty entry means no passphrase. A nonempty passphrase must be entered twice.Terminal echo is disabled while the passphrase is read.

Passphrase input requires an interactive POSIX terminal and cannot be pipedthrough standard input.

Output resembles:

    BIP-39 Derivation

Mnemonic:   abandon ... about
Passphrase: set (not displayed)
Seed:       c55257c360c07c72...

The seed is 64 bytes displayed as 128 lowercase hexadecimal characters. Thepassphrase itself is never printed.

Seed derivation currently rejects non-ASCII mnemonic or passphrase input.

If terminal echo remains disabled after an abnormal external failure:

stty echo

Wordlists

The compiled official English wordlist is used unless --wordlist is supplied.

./build/seeds --wordlist english-seeds.txt

An external wordlist must contain:

exactly 2,048 lines;

one word per line;

no empty lines;

no duplicate words.

Word content and ordering are significant. A custom wordlist will notinteroperate with standard wallets unless they use the identical list in theidentical order.

BIP-39 requires non-ASCII wordlists to use UTF-8 NFKD normalization. Thisprogram does not perform Unicode normalization.

Output

Normal output contains:

Seed Words — the mnemonic words in order.

Tiny Seed — each word's zero-based 11-bit wordlist index.

Tiny Seed uses _ for zero and █ for one:

wordlist[0]    = 00000000000
wordlist[2047] = 11111111111

Do not add one before recording or stamping an index. Tiny Seed represents thesame recovery secret as the mnemonic and requires the same protection.

With --show-entropy, the program also displays entropy, checksum bits, entropylength, and checksum length. This output can recreate the mnemonic.

With --show-seed, the mnemonic sentence and 64-byte seed are appended afterTiny Seed.

Errors

Invalid command-line arguments, unsupported word counts, mutually exclusiveentropy modes, malformed wordlists, OpenSSL failures, incomplete input, invaliddice or card entries, duplicate cards, mismatched passphrases, and non-ASCIIseed-derivation input cause a nonzero exit status.

Security Considerations

Before using similar software with real wallet recovery material:

review and test the implementation independently;

compare results against official BIP-39 vectors;

build from reviewed source;

use a trusted and preferably offline computer;

prevent terminal output from being logged or retained;

protect dice rolls and card orderings from observation;

verify external wordlists and their ordering;

test wallet recovery before funding it;

securely erase temporary output where practical.

Hashing conditions entropy but does not create unpredictability absent from itsinputs. Physical-only modes are reproducible, but their security depends on thequality and secrecy of the physical process.

The executable, operating system, terminal, display server, shell, storage,backups, camera view, and physical surroundings remain part of the trustboundary.

No warranty is made that this software is suitable for securing funds.

License

This project is licensed under the GNU General Public License version 3. SeeLICENSE for details.


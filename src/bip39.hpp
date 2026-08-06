// src/bip39.hpp

#ifndef BIP39_HPP
#define BIP39_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bip39 {

constexpr std::size_t wordlist_size{2048};
constexpr std::size_t bits_per_word{11};
constexpr std::size_t sha256_size{32};
constexpr std::size_t seed_size{64};

using Bytes = std::vector<unsigned char>;
using Digest = std::array<unsigned char, sha256_size>;
using Seed = std::array<unsigned char, seed_size>;

std::size_t entropy_bytes_for_word_count(std::size_t word_count);

Digest sha256(const Bytes& data);

std::vector<std::uint16_t> make_indices(const Bytes& entropy,
                                        const Digest& digest,
                                        std::size_t word_count);

// This project currently supports ASCII input only. BIP-39 requires NFKD
// normalization for non-ASCII mnemonic and passphrase text.
Seed derive_seed(std::string_view mnemonic, std::string_view passphrase = {});

std::vector<std::string> make_english_word_list();

} // namespace bip39

#endif


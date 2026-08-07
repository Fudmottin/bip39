// src/entropy.hpp

#ifndef ENTROPY_HPP
#define ENTROPY_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "bip39.hpp"

namespace entropy {

constexpr std::size_t cards_per_deck{52};
constexpr std::size_t canonical_card_size{2};
constexpr std::size_t canonical_deck_size{cards_per_deck * canonical_card_size};

using ZeroBasedDiceRolls = std::vector<unsigned char>;

std::size_t mixed_dice_roll_count(std::size_t byte_count);
std::size_t dice_only_roll_count(std::size_t byte_count);
std::size_t cards_only_deck_count(std::size_t byte_count);

bip39::Bytes mix_dice_entropy(const ZeroBasedDiceRolls& rolls,
                              const bip39::Bytes& system_random,
                              std::size_t byte_count);

bip39::Bytes dice_only_entropy(std::string_view rolls, std::size_t byte_count);

// Return a lowercase two-character card name. Ten may be entered as either
// "10" or "t"; for example, "10S" and "ts" both become "ts".
std::string normalize_card(std::string_view card);

bip39::Bytes mix_card_entropy(std::string_view canonical_deck,
                              const bip39::Bytes& system_random,
                              std::size_t byte_count);

// A second deck must be supplied only for 32-byte entropy. It represents a
// second independently shuffled ordering of the same physical 52-card deck.
bip39::Bytes cards_only_entropy(std::string_view first_canonical_deck,
                                std::string_view second_canonical_deck,
                                std::size_t byte_count);

} // namespace entropy

#endif

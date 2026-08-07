// src/entropy.cpp

#include "entropy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace entropy {
namespace {

constexpr std::string_view mixed_dice_domain{"bip39-dice-v1"};
constexpr std::string_view mixed_cards_domain{"bip39-cards-v1"};
constexpr std::string_view cards_only_domain{"bip39-cards-only-v1"};
constexpr std::string_view card_ranks{"a23456789tjqk"};
constexpr std::string_view card_suits{"cdhs"};

void require_supported_entropy_size(std::size_t byte_count) {
   switch (byte_count) {
   case 16:
   case 20:
   case 24:
   case 28:
   case 32:
      return;
   default:
      throw std::invalid_argument{"unsupported BIP-39 entropy length"};
   }
}

void append_uint16_be(bip39::Bytes& bytes, std::uint16_t value) {
   bytes.push_back(static_cast<unsigned char>(value >> 8U));
   bytes.push_back(static_cast<unsigned char>(value & 0xffU));
}

void append_text(bip39::Bytes& bytes, std::string_view text) {
   bytes.insert(bytes.end(), text.begin(), text.end());
}

bip39::Bytes truncate_digest(const bip39::Digest& digest,
                             std::size_t byte_count) {
   bip39::Bytes entropy(byte_count);
   std::copy_n(digest.begin(), byte_count, entropy.begin());
   return entropy;
}

char lowercase_ascii(char character) {
   const auto value = static_cast<unsigned char>(character);
   return static_cast<char>(std::tolower(value));
}

std::string_view trim_ascii_space(std::string_view text) {
   const auto is_space = [](char character) {
      return std::isspace(static_cast<unsigned char>(character)) != 0;
   };

   while (!text.empty() && is_space(text.front())) {
      text.remove_prefix(1);
   }

   while (!text.empty() && is_space(text.back())) {
      text.remove_suffix(1);
   }

   return text;
}

std::size_t card_index(char rank, char suit) {
   const auto rank_position = card_ranks.find(rank);
   const auto suit_position = card_suits.find(suit);

   if (rank_position == std::string_view::npos ||
       suit_position == std::string_view::npos) {
      throw std::invalid_argument{"invalid canonical card name"};
   }

   return suit_position * card_ranks.size() + rank_position;
}

void validate_canonical_deck(std::string_view deck) {
   if (deck.size() != canonical_deck_size) {
      throw std::invalid_argument{"a canonical deck must contain 52 cards"};
   }

   std::array<bool, cards_per_deck> seen{};

   for (std::size_t offset = 0; offset < deck.size();
        offset += canonical_card_size) {
      const auto index = card_index(deck[offset], deck[offset + 1]);

      if (seen[index]) {
         throw std::invalid_argument{
            "canonical deck contains a duplicate card"};
      }

      seen[index] = true;
   }
}

} // namespace

std::size_t mixed_dice_roll_count(std::size_t byte_count) {
   switch (byte_count) {
   case 16:
      return 75;
   case 20:
      return 87;
   case 24:
      return 100;
   case 28:
      return 112;
   case 32:
      return 124;
   default:
      throw std::invalid_argument{"unsupported BIP-39 entropy length"};
   }
}

std::size_t dice_only_roll_count(std::size_t byte_count) {
   switch (byte_count) {
   case 16:
      return 50;
   case 20:
      return 62;
   case 24:
      return 75;
   case 28:
      return 87;
   case 32:
      // COLDCARD and SeedSigner convention. Ninety-nine fair rolls contain
      // slightly less than 256 bits of nominal entropy, but this count is
      // retained for interoperability.
      return 99;
   default:
      throw std::invalid_argument{"unsupported BIP-39 entropy length"};
   }
}

std::size_t cards_only_deck_count(std::size_t byte_count) {
   require_supported_entropy_size(byte_count);
   return byte_count == 32 ? 2 : 1;
}

bip39::Bytes mix_dice_entropy(const ZeroBasedDiceRolls& rolls,
                              const bip39::Bytes& system_random,
                              std::size_t byte_count) {
   require_supported_entropy_size(byte_count);

   if (rolls.size() != mixed_dice_roll_count(byte_count)) {
      throw std::invalid_argument{"incorrect number of mixed dice rolls"};
   }

   if (!std::all_of(rolls.begin(), rolls.end(),
                    [](unsigned char roll) { return roll <= 5U; })) {
      throw std::invalid_argument{
         "mixed dice rolls must be values 0 through 5"};
   }

   if (system_random.size() != bip39::sha256_size) {
      throw std::invalid_argument{
         "mixed dice mode requires 32 bytes of system randomness"};
   }

   const auto entropy_bit_count = byte_count * 8U;

   bip39::Bytes conditioner_input;
   conditioner_input.reserve(mixed_dice_domain.size() + 4U + rolls.size() +
                             system_random.size());
   append_text(conditioner_input, mixed_dice_domain);
   append_uint16_be(conditioner_input,
                    static_cast<std::uint16_t>(entropy_bit_count));
   append_uint16_be(conditioner_input,
                    static_cast<std::uint16_t>(rolls.size()));
   conditioner_input.insert(conditioner_input.end(), rolls.begin(),
                            rolls.end());
   conditioner_input.insert(conditioner_input.end(), system_random.begin(),
                            system_random.end());

   return truncate_digest(bip39::sha256(conditioner_input), byte_count);
}

bip39::Bytes dice_only_entropy(std::string_view rolls, std::size_t byte_count) {
   require_supported_entropy_size(byte_count);

   if (rolls.size() != dice_only_roll_count(byte_count)) {
      throw std::invalid_argument{"incorrect number of dice-only rolls"};
   }

   if (!std::all_of(rolls.begin(), rolls.end(),
                    [](char roll) { return roll >= '1' && roll <= '6'; })) {
      throw std::invalid_argument{
         "dice-only rolls must be ASCII digits 1 through 6"};
   }

   const bip39::Bytes input{rolls.begin(), rolls.end()};
   return truncate_digest(bip39::sha256(input), byte_count);
}

std::string normalize_card(std::string_view card) {
   card = trim_ascii_space(card);

   char rank{};
   char suit{};

   if (card.size() == 2) {
      rank = lowercase_ascii(card[0]);
      suit = lowercase_ascii(card[1]);
   } else if (card.size() == 3 && card[0] == '1' && card[1] == '0') {
      rank = 't';
      suit = lowercase_ascii(card[2]);
   } else {
      throw std::invalid_argument{
         "card must be a rank followed by a suit, such as as, 10d, or qh"};
   }

   static_cast<void>(card_index(rank, suit));
   return std::string{rank, suit};
}

bip39::Bytes mix_card_entropy(std::string_view canonical_deck,
                              const bip39::Bytes& system_random,
                              std::size_t byte_count) {
   require_supported_entropy_size(byte_count);
   validate_canonical_deck(canonical_deck);

   if (system_random.size() != bip39::sha256_size) {
      throw std::invalid_argument{
         "mixed cards mode requires 32 bytes of system randomness"};
   }

   bip39::Bytes conditioner_input;
   conditioner_input.reserve(mixed_cards_domain.size() + canonical_deck.size() +
                             system_random.size());
   append_text(conditioner_input, mixed_cards_domain);
   append_text(conditioner_input, canonical_deck);
   conditioner_input.insert(conditioner_input.end(), system_random.begin(),
                            system_random.end());

   return truncate_digest(bip39::sha256(conditioner_input), byte_count);
}

bip39::Bytes cards_only_entropy(std::string_view first_canonical_deck,
                                std::string_view second_canonical_deck,
                                std::size_t byte_count) {
   const auto required_decks = cards_only_deck_count(byte_count);
   validate_canonical_deck(first_canonical_deck);

   if (required_decks == 1) {
      if (!second_canonical_deck.empty()) {
         throw std::invalid_argument{
            "a second deck is used only for 256-bit card-only entropy"};
      }
   } else {
      validate_canonical_deck(second_canonical_deck);

      if (first_canonical_deck == second_canonical_deck) {
         throw std::invalid_argument{
            "the second card-only shuffle must differ from the first"};
      }
   }

   bip39::Bytes conditioner_input;
   conditioner_input.reserve(cards_only_domain.size() +
                             first_canonical_deck.size() +
                             second_canonical_deck.size());
   append_text(conditioner_input, cards_only_domain);
   append_text(conditioner_input, first_canonical_deck);
   append_text(conditioner_input, second_canonical_deck);

   return truncate_digest(bip39::sha256(conditioner_input), byte_count);
}

} // namespace entropy

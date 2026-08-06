// tests/test.cpp

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bip39.hpp"

namespace {
struct TestVector {
   std::string_view entropy_hex;
   std::string_view mnemonic;
};

// English vectors published by the BIP-39 reference implementation.
// This project currently tests entropy-to-mnemonic conversion only.
constexpr std::array<TestVector, 24> test_vectors{{
   {"00000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about"},
   {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank "
    "yellow"},
   {"80808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice "
    "cage above"},
   {"ffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
   {"000000000000000000000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon agent"},
   {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank "
    "year wave sausage worth useful legal will"},
   {"808080808080808080808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice "
    "cage absurd amount doctor acoustic avoid letter always"},
   {"ffffffffffffffffffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "when"},
   {"0000000000000000000000000000000000000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon art"},
   {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank "
    "year wave sausage worth useful legal winner thank year wave sausage "
    "worth title"},
   {"8080808080808080808080808080808080808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice "
    "cage absurd amount doctor acoustic avoid letter advice cage absurd "
    "amount doctor acoustic bless"},
   {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo vote"},
   {"9e885d952ad362caeb4efe34a8e91bd2",
    "ozone drill grab fiber curtain grace pudding thank cruise elder eight "
    "picnic"},
   {"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
    "gravity machine north sort system female filter attitude volume fold club "
    "stay feature office ecology stable narrow fog"},
   {"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    "hamster diagram private dutch cause delay private meat slide toddler "
    "razor book happy fancy gospel tennis maple dilemma loan word shrug "
    "inflict delay length"},
   {"c0ba5a8e914111210f2bd131f3d5e08d",
    "scheme spot photo card baby mountain device kick cradle pact join borrow"},
   {"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
    "horn tenant knee talent sponsor spell gate clip pulse soap slush warm "
    "silver nephew swap uncle crack brave"},
   {"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
    "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft "
    "ostrich alcohol speed nation flash devote level hobby quick inner drive "
    "ghost inside"},
   {"23db8160a31d3e0dca3688ed941adbf3",
    "cat swing flag economy stadium alone churn speed unique patch report "
    "train"},
   {"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
    "light rule cinnamon wrap drastic word pride squirrel upgrade then income "
    "fatal apart sustain crack supply proud access"},
   {"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
    "all hour make first leader extend hole alien behind guard gospel lava "
    "path output census museum junior mass reopen famous sing advance salt "
    "reform"},
   {"f30f8c1da665478f49b001d94c5fc452",
    "vessel ladder alter error federal sibling chat ability sun glass valve "
    "picture"},
   {"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
    "scissors invite lock maple supreme raw rapid void congress muscle digital "
    "elegant little brisk hair mango congress clump"},
   {"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
    "void come effort suffer camp survey warrior heavy shoot primary clutch "
    "crush open amazing screen patrol group space point ten exist slush "
    "involve unfold"},
}};

unsigned char hex_value(char digit) {
   if (digit >= '0' && digit <= '9') {
      return static_cast<unsigned char>(digit - '0');
   }
   if (digit >= 'a' && digit <= 'f') {
      return static_cast<unsigned char>(digit - 'a' + 10);
   }
   if (digit >= 'A' && digit <= 'F') {
      return static_cast<unsigned char>(digit - 'A' + 10);
   }

   throw std::invalid_argument{"invalid hexadecimal digit"};
}

bip39::Bytes bytes_from_hex(std::string_view text) {
   if (text.size() % 2 != 0) {
      throw std::invalid_argument{"hexadecimal entropy must contain whole bytes"};
   }

   bip39::Bytes bytes;
   bytes.reserve(text.size() / 2);

   for (std::size_t position = 0; position < text.size(); position += 2) {
      const auto high = hex_value(text[position]);
      const auto low = hex_value(text[position + 1]);
      bytes.push_back(static_cast<unsigned char>((high << 4U) | low));
   }

   return bytes;
}

std::size_t count_words(std::string_view mnemonic) {
   if (mnemonic.empty()) {
      return 0;
   }

   return 1 + static_cast<std::size_t>(
                 std::count(mnemonic.begin(), mnemonic.end(), ' '));
}

std::string make_mnemonic(const std::vector<std::string>& words,
                          const std::vector<std::uint16_t>& indices) {
   std::string mnemonic;

   for (std::size_t position = 0; position < indices.size(); ++position) {
      if (position != 0) {
         mnemonic += ' ';
      }
      mnemonic += words[indices[position]];
   }

   return mnemonic;
}

template <typename Function>
bool expect_invalid_argument(std::string_view description, Function&& function) {
   try {
      std::forward<Function>(function)();
   } catch (const std::invalid_argument&) {
      return true;
   } catch (const std::exception& error) {
      std::cerr << description << " threw the wrong exception: "
                << error.what() << '\n';
      return false;
   } catch (...) {
      std::cerr << description << " threw a non-standard exception\n";
      return false;
   }

   std::cerr << description << " did not throw std::invalid_argument\n";
   return false;
}

bool test_entropy_sizes() {
   constexpr std::array<std::pair<std::size_t, std::size_t>, 5> cases{{
      {12, 16},
      {15, 20},
      {18, 24},
      {21, 28},
      {24, 32},
   }};

   for (const auto& [words, bytes] : cases) {
      if (bip39::entropy_bytes_for_word_count(words) != bytes) {
         std::cerr << "word-count mapping failed for " << words << " words\n";
         return false;
      }
   }

   return true;
}

bool test_unsupported_word_counts() {
   struct InvalidCase {
      std::size_t word_count;
      std::size_t entropy_bytes;
   };

   // Several cases deliberately satisfy the old bit-count arithmetic despite
   // not being permitted by BIP-39: 0/0, 3/4, 6/8, 9/12, and 27/36.
   constexpr std::array<InvalidCase, 10> invalid_cases{{
      {0, 0},
      {3, 4},
      {6, 8},
      {9, 12},
      {11, 16},
      {13, 16},
      {16, 20},
      {23, 32},
      {25, 32},
      {27, 36},
   }};

   const bip39::Digest digest{};
   bool passed{true};

   for (const auto& [word_count, byte_count] : invalid_cases) {
      const auto mapping_description =
         "entropy mapping for unsupported word count " +
         std::to_string(word_count);

      if (!expect_invalid_argument(mapping_description, [word_count] {
             static_cast<void>(
                bip39::entropy_bytes_for_word_count(word_count));
          })) {
         passed = false;
      }

      const bip39::Bytes entropy(byte_count);
      const auto indices_description =
         "index generation for unsupported word count " +
         std::to_string(word_count);

      if (!expect_invalid_argument(
             indices_description, [&entropy, &digest, word_count] {
                static_cast<void>(
                   bip39::make_indices(entropy, digest, word_count));
             })) {
         passed = false;
      }
   }

   return passed;
}

bool test_invalid_entropy_sizes() {
   constexpr std::array<std::pair<std::size_t, std::size_t>, 5> valid_cases{{
      {12, 16},
      {15, 20},
      {18, 24},
      {21, 28},
      {24, 32},
   }};

   const bip39::Digest digest{};
   bool passed{true};

   for (const auto& [word_count, expected_bytes] : valid_cases) {
      const std::array<std::size_t, 2> invalid_sizes{
         expected_bytes - 1,
         expected_bytes + 1,
      };

      for (const auto byte_count : invalid_sizes) {
         const bip39::Bytes entropy(byte_count);
         const auto description =
            "index generation for " + std::to_string(byte_count) +
            " entropy bytes and " + std::to_string(word_count) + " words";

         if (!expect_invalid_argument(
                description, [&entropy, &digest, word_count] {
                   static_cast<void>(
                      bip39::make_indices(entropy, digest, word_count));
                })) {
            passed = false;
         }
      }
   }

   return passed;
}

bool test_vector(std::size_t number,
                 const TestVector& vector,
                 const std::vector<std::string>& words) {
   const auto entropy = bytes_from_hex(vector.entropy_hex);
   const auto expected_word_count = count_words(vector.mnemonic);
   const auto digest = bip39::sha256(entropy);
   const auto indices = bip39::make_indices(entropy, digest, expected_word_count);
   const auto actual = make_mnemonic(words, indices);

   if (bip39::entropy_bytes_for_word_count(expected_word_count) != entropy.size()) {
      std::cerr << "vector " << number
                << " has inconsistent entropy and mnemonic lengths\n";
      return false;
   }

   if (actual == vector.mnemonic) {
      return true;
   }

   std::cerr << "vector " << number << " failed\n"
             << "entropy: " << vector.entropy_hex << '\n'
             << "expected: " << vector.mnemonic << '\n'
             << "actual:   " << actual << '\n';
   return false;
}
} // namespace

int main() try {
   std::size_t failure_count{};

   if (!test_entropy_sizes()) {
      ++failure_count;
   }

   if (!test_unsupported_word_counts()) {
      ++failure_count;
   }

   if (!test_invalid_entropy_sizes()) {
      ++failure_count;
   }

   const auto words = bip39::make_english_word_list();
   if (words.size() != bip39::wordlist_size) {
      std::cerr << "compiled English wordlist does not contain 2048 words\n";
      ++failure_count;
   } else {
      for (std::size_t index = 0; index < test_vectors.size(); ++index) {
         if (!test_vector(index + 1, test_vectors[index], words)) {
            ++failure_count;
         }
      }
   }

   if (failure_count != 0) {
      std::cerr << failure_count << " test group(s) failed\n";
      return 1;
   }

   std::cout << test_vectors.size()
             << " BIP-39 English mnemonic vectors passed\n"
             << "BIP-39 input validation passed\n";
   return 0;
} catch (const std::exception& error) {
   std::cerr << "test error: " << error.what() << '\n';
   return 1;
}


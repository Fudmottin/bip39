#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bip39.hpp"
#include "entropy.hpp"

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

// The BIP-39 reference vectors use the passphrase "TREZOR".
constexpr std::array<std::string_view, 24> expected_seeds{{
   "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
   "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
   "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
   "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
   "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30"
   "fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
   "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
   "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
   "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca"
   "06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
   "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0"
   "c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
   "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc2"
   "7fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
   "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a7"
   "6379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
   "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
   "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
   "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a40"
   "21b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
   "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a0"
   "9e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
   "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
   "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
   "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e547"
   "6c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
   "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68"
   "e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
   "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d2"
   "0b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
   "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fc"
   "a05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
   "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853"
   "c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
   "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6"
   "fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
   "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b592"
   "05a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
   "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b7"
   "82925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
   "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf"
   "6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
   "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090b"
   "f9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
   "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4"
   "f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
   "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f"
   "0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
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
      throw std::invalid_argument{
         "hexadecimal entropy must contain whole bytes"};
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

template<typename Range>
std::string bytes_to_hex(const Range& bytes) {
   std::ostringstream output;

   for (const auto byte : bytes) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(byte);
   }

   return output.str();
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

template<typename Function>
bool expect_invalid_argument(std::string_view description,
                             Function&& function) {
   try {
      std::forward<Function>(function)();
   } catch (const std::invalid_argument&) {
      return true;
   } catch (const std::exception& error) {
      std::cerr << description << " threw the wrong exception: " << error.what()
                << '\n';
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
             static_cast<void>(bip39::entropy_bytes_for_word_count(word_count));
          })) {
         passed = false;
      }

      const bip39::Bytes entropy(byte_count);
      const auto indices_description =
         "index generation for unsupported word count " +
         std::to_string(word_count);

      if (!expect_invalid_argument(indices_description, [&entropy, &digest,
                                                         word_count] {
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

         if (!expect_invalid_argument(description, [&entropy, &digest,
                                                    word_count] {
                static_cast<void>(
                   bip39::make_indices(entropy, digest, word_count));
             })) {
            passed = false;
         }
      }
   }

   return passed;
}

bool test_seed_input_validation() {
   bool passed{true};
   std::string non_ascii_mnemonic{"abandon"};
   non_ascii_mnemonic.push_back(static_cast<char>(0x80));

   if (!expect_invalid_argument("non-ASCII mnemonic", [&non_ascii_mnemonic] {
          static_cast<void>(bip39::derive_seed(non_ascii_mnemonic));
       })) {
      passed = false;
   }

   std::string non_ascii_passphrase;
   non_ascii_passphrase.push_back(static_cast<char>(0x80));

   if (!expect_invalid_argument(
          "non-ASCII passphrase", [&non_ascii_passphrase] {
             static_cast<void>(bip39::derive_seed(test_vectors.front().mnemonic,
                                                  non_ascii_passphrase));
          })) {
      passed = false;
   }

   constexpr std::string_view expected_empty_passphrase_seed{
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
      "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"};
   const auto empty_passphrase_seed =
      bip39::derive_seed(test_vectors.front().mnemonic);

   if (bytes_to_hex(empty_passphrase_seed) != expected_empty_passphrase_seed) {
      std::cerr << "empty-passphrase seed vector failed\n";
      passed = false;
   }

   if (empty_passphrase_seed ==
       bip39::derive_seed(test_vectors.front().mnemonic, "TREZOR")) {
      std::cerr << "different passphrases produced the same seed\n";
      passed = false;
   }

   return passed;
}

bool test_dice_entropy(const std::vector<std::string>& words) {
   struct DiceVector {
      std::string_view rolls;
      std::size_t byte_count;
      std::size_t word_count;
      std::string_view entropy_hex;
      std::string_view mnemonic;
   };

   constexpr std::array<DiceVector, 2> vectors{{
      {"65515223131652132161133154444123616466443112153441", 16, 12,
       "6cb09af855050dcde6fe2adc3181c250",
       "hole luggage safe present express tragic orbit shed switch metal "
       "identify path"},
      {"655152231316521321611331544441236164664431121534415633526456254462"
       "245546236542364246312613322234612",
       32, 24,
       "51531761ec7a738946e0b9f46bb11320a695495430e345c14f01ad8b3b898a6d",
       "eyebrow obvious such suggest poet seven breeze blame virtual frown "
       "dynamic donor harsh pigeon express broccoli easy apology scatter "
       "force recipe shadow claim radio"},
   }};

   constexpr std::array<std::pair<std::size_t, std::size_t>, 5> roll_counts{{
      {16, 50},
      {20, 62},
      {24, 75},
      {28, 87},
      {32, 99},
   }};

   bool passed{true};

   for (const auto& [byte_count, expected_rolls] : roll_counts) {
      if (entropy::dice_only_roll_count(byte_count) != expected_rolls) {
         std::cerr << "dice-only roll-count mapping failed for " << byte_count
                   << " entropy bytes\n";
         passed = false;
      }
   }

   for (const auto& vector : vectors) {
      const auto actual_entropy =
         entropy::dice_only_entropy(vector.rolls, vector.byte_count);

      if (bytes_to_hex(actual_entropy) != vector.entropy_hex) {
         std::cerr << "dice-only entropy vector failed for "
                   << vector.word_count << " words\n"
                   << "expected: " << vector.entropy_hex << '\n'
                   << "actual:   " << bytes_to_hex(actual_entropy) << '\n';
         passed = false;
         continue;
      }

      const auto digest = bip39::sha256(actual_entropy);
      const auto indices =
         bip39::make_indices(actual_entropy, digest, vector.word_count);
      const auto actual_mnemonic = make_mnemonic(words, indices);

      if (actual_mnemonic != vector.mnemonic) {
         std::cerr << "dice-only mnemonic vector failed for "
                   << vector.word_count << " words\n"
                   << "expected: " << vector.mnemonic << '\n'
                   << "actual:   " << actual_mnemonic << '\n';
         passed = false;
      }
   }

   auto invalid_rolls = std::string{vectors.front().rolls};
   invalid_rolls.front() = '0';

   if (!expect_invalid_argument(
          "dice-only roll outside 1 through 6", [&invalid_rolls] {
             static_cast<void>(entropy::dice_only_entropy(invalid_rolls, 16));
          })) {
      passed = false;
   }

   if (!expect_invalid_argument("incorrect dice-only roll count", [&vectors] {
          static_cast<void>(
             entropy::dice_only_entropy(vectors.front().rolls.substr(1), 16));
       })) {
      passed = false;
   }

   entropy::ZeroBasedDiceRolls mixed_rolls(75);
   for (std::size_t index = 0; index < mixed_rolls.size(); ++index) {
      mixed_rolls[index] = static_cast<unsigned char>(index % 6U);
   }

   bip39::Bytes system_random(bip39::sha256_size);
   for (std::size_t index = 0; index < system_random.size(); ++index) {
      system_random[index] = static_cast<unsigned char>(index);
   }

   constexpr std::string_view expected_mixed_entropy{
      "177835c5facc99776006143dc364d5b9"};
   const auto actual_mixed_entropy =
      entropy::mix_dice_entropy(mixed_rolls, system_random, 16);

   if (bytes_to_hex(actual_mixed_entropy) != expected_mixed_entropy) {
      std::cerr << "mixed dice entropy vector failed\n"
                << "expected: " << expected_mixed_entropy << '\n'
                << "actual:   " << bytes_to_hex(actual_mixed_entropy) << '\n';
      passed = false;
   }

   return passed;
}

std::string make_ordered_deck() {
   constexpr std::string_view ranks{"a23456789tjqk"};
   constexpr std::string_view suits{"cdhs"};

   std::string deck;
   deck.reserve(entropy::canonical_deck_size);

   for (const auto suit : suits) {
      for (const auto rank : ranks) {
         deck += rank;
         deck += suit;
      }
   }

   return deck;
}

std::string reverse_deck(std::string_view deck) {
   std::string reversed;
   reversed.reserve(deck.size());

   for (std::size_t offset = deck.size(); offset != 0;
        offset -= entropy::canonical_card_size) {
      reversed.append(deck.substr(offset - entropy::canonical_card_size,
                                  entropy::canonical_card_size));
   }

   return reversed;
}

bool test_card_entropy() {
   bool passed{true};

   if (entropy::normalize_card(" AS ") != "as" ||
       entropy::normalize_card("10D") != "td" ||
       entropy::normalize_card("Th") != "th") {
      std::cerr << "card-name normalization failed\n";
      passed = false;
   }

   constexpr std::array<std::string_view, 4> invalid_cards{"1s", "11s", "xz",
                                                           "ace of spades"};

   for (const auto card : invalid_cards) {
      if (!expect_invalid_argument("invalid card name " + std::string{card},
                                   [card] {
                                      static_cast<void>(
                                         entropy::normalize_card(card));
                                   })) {
         passed = false;
      }
   }

   constexpr std::array<std::pair<std::size_t, std::size_t>, 5> deck_counts{{
      {16, 1},
      {20, 1},
      {24, 1},
      {28, 1},
      {32, 2},
   }};

   for (const auto& [byte_count, expected_decks] : deck_counts) {
      if (entropy::cards_only_deck_count(byte_count) != expected_decks) {
         std::cerr << "cards-only deck-count mapping failed for " << byte_count
                   << " entropy bytes\n";
         passed = false;
      }
   }

   const auto first_deck = make_ordered_deck();
   const auto second_deck = reverse_deck(first_deck);

   bip39::Bytes system_random(bip39::sha256_size);
   for (std::size_t index = 0; index < system_random.size(); ++index) {
      system_random[index] = static_cast<unsigned char>(index);
   }

   constexpr std::string_view expected_mixed_entropy{
      "458cbab4c71fc9423e80c62e9c1633ad"};
   const auto mixed_entropy =
      entropy::mix_card_entropy(first_deck, system_random, 16);

   if (bytes_to_hex(mixed_entropy) != expected_mixed_entropy) {
      std::cerr << "mixed card entropy vector failed\n"
                << "expected: " << expected_mixed_entropy << '\n'
                << "actual:   " << bytes_to_hex(mixed_entropy) << '\n';
      passed = false;
   }

   constexpr std::string_view expected_one_deck_entropy{
      "8a6d032c45ea38942575103d0e032b89"};
   const auto one_deck_entropy =
      entropy::cards_only_entropy(first_deck, {}, 16);

   if (bytes_to_hex(one_deck_entropy) != expected_one_deck_entropy) {
      std::cerr << "one-deck card-only entropy vector failed\n"
                << "expected: " << expected_one_deck_entropy << '\n'
                << "actual:   " << bytes_to_hex(one_deck_entropy) << '\n';
      passed = false;
   }

   constexpr std::string_view expected_two_deck_entropy{
      "99151c079169ea4a0c81a3ec0f778575db2c80fa91149c6efea0600d8b341196"};
   const auto two_deck_entropy =
      entropy::cards_only_entropy(first_deck, second_deck, 32);

   if (bytes_to_hex(two_deck_entropy) != expected_two_deck_entropy) {
      std::cerr << "two-deck card-only entropy vector failed\n"
                << "expected: " << expected_two_deck_entropy << '\n'
                << "actual:   " << bytes_to_hex(two_deck_entropy) << '\n';
      passed = false;
   }

   auto duplicate_deck = first_deck;
   duplicate_deck.replace(duplicate_deck.size() - entropy::canonical_card_size,
                          entropy::canonical_card_size,
                          duplicate_deck.substr(0,
                                                entropy::canonical_card_size));

   if (!expect_invalid_argument("duplicate card in canonical deck",
                                [&duplicate_deck, &system_random] {
                                   static_cast<void>(entropy::mix_card_entropy(
                                      duplicate_deck, system_random, 16));
                                })) {
      passed = false;
   }

   if (!expect_invalid_argument(
          "one deck for 256-bit card-only entropy", [&first_deck] {
             static_cast<void>(entropy::cards_only_entropy(first_deck, {}, 32));
          })) {
      passed = false;
   }

   if (!expect_invalid_argument("second deck for shorter card-only entropy",
                                [&first_deck, &second_deck] {
                                   static_cast<void>(
                                      entropy::cards_only_entropy(first_deck,
                                                                  second_deck,
                                                                  16));
                                })) {
      passed = false;
   }

   if (!expect_invalid_argument("identical card-only shuffles", [&first_deck] {
          static_cast<void>(
             entropy::cards_only_entropy(first_deck, first_deck, 32));
       })) {
      passed = false;
   }

   const bip39::Bytes short_system_random(bip39::sha256_size - 1);

   if (!expect_invalid_argument("short mixed-card system randomness",
                                [&first_deck, &short_system_random] {
                                   static_cast<void>(entropy::mix_card_entropy(
                                      first_deck, short_system_random, 16));
                                })) {
      passed = false;
   }

   return passed;
}

bool test_vector(std::size_t number, const TestVector& vector,
                 const std::vector<std::string>& words) {
   const auto entropy = bytes_from_hex(vector.entropy_hex);
   const auto expected_word_count = count_words(vector.mnemonic);
   const auto digest = bip39::sha256(entropy);
   const auto indices =
      bip39::make_indices(entropy, digest, expected_word_count);
   const auto actual = make_mnemonic(words, indices);

   if (bip39::entropy_bytes_for_word_count(expected_word_count) !=
       entropy.size()) {
      std::cerr << "vector " << number
                << " has inconsistent entropy and mnemonic lengths\n";
      return false;
   }

   if (actual != vector.mnemonic) {
      std::cerr << "mnemonic vector " << number << " failed\n"
                << "entropy: " << vector.entropy_hex << '\n'
                << "expected: " << vector.mnemonic << '\n'
                << "actual:   " << actual << '\n';
      return false;
   }

   const auto actual_seed = bip39::derive_seed(vector.mnemonic, "TREZOR");
   const auto actual_seed_hex = bytes_to_hex(actual_seed);

   if (actual_seed_hex != expected_seeds[number - 1]) {
      std::cerr << "seed vector " << number << " failed\n"
                << "expected: " << expected_seeds[number - 1] << '\n'
                << "actual:   " << actual_seed_hex << '\n';
      return false;
   }

   return true;
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

   if (!test_seed_input_validation()) {
      ++failure_count;
   }

   if (!test_card_entropy()) {
      ++failure_count;
   }

   const auto words = bip39::make_english_word_list();
   if (words.size() != bip39::wordlist_size) {
      std::cerr << "compiled English wordlist does not contain 2048 words\n";
      ++failure_count;
   } else {
      if (!test_dice_entropy(words)) {
         ++failure_count;
      }

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
             << " BIP-39 English mnemonic and seed vectors passed\n"
             << "BIP-39 input validation passed\n"
             << "BIP-39 ASCII seed derivation passed\n"
             << "Dice entropy derivation passed\n"
             << "Card entropy derivation passed\n";
   return 0;
} catch (const std::exception& error) {
   std::cerr << "test error: " << error.what() << '\n';
   return 1;
}

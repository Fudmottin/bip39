#include <boost/program_options.hpp>

#include <algorithm>
#include <array>
#include <bitset>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <termios.h>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <vector>

#include "bip39.hpp"
#include "entropy.hpp"

namespace {

using bip39::Bytes;
using bip39::Digest;
using bip39::Seed;

namespace po = boost::program_options;

struct ProgramOptions {
   ProgramOptions()
      : wordlist_filename{}
      , word_count{12}
      , show_entropy{false}
      , show_help{false}
      , show_seed{false}
      , use_dice{false}
      , use_dice_only{false}
      , use_cards{false}
      , use_cards_only{false} {}

   std::string wordlist_filename;
   std::size_t word_count;
   bool show_entropy;
   bool show_help;
   bool show_seed;
   bool use_dice;
   bool use_dice_only;
   bool use_cards;
   bool use_cards_only;
};

class SensitiveString {
 public:
   SensitiveString() = default;
   SensitiveString(const SensitiveString&) = delete;
   SensitiveString& operator=(const SensitiveString&) = delete;
   SensitiveString(SensitiveString&&) = delete;
   SensitiveString& operator=(SensitiveString&&) = delete;

   ~SensitiveString() { OPENSSL_cleanse(value_.data(), value_.size()); }

   std::string& value() { return value_; }
   const std::string& value() const { return value_; }

 private:
   std::string value_;
};

volatile std::sig_atomic_t caught_signal{};

void remember_signal(int signal_number) { caught_signal = signal_number; }

class SignalGuard {
 public:
   SignalGuard() {
      caught_signal = 0;

      struct sigaction action{};
      action.sa_handler = remember_signal;
      sigemptyset(&action.sa_mask);
      action.sa_flags = 0;

      for (std::size_t index = 0; index < signals_.size(); ++index) {
         if (::sigaction(signals_[index], &action, &original_[index]) == -1) {
            const auto error = errno;
            restore();
            throw std::system_error{error, std::generic_category(),
                                    "could not install signal handler"};
         }

         ++installed_;
      }
   }

   SignalGuard(const SignalGuard&) = delete;
   SignalGuard& operator=(const SignalGuard&) = delete;

   ~SignalGuard() { restore(); }

   int signal_number() const { return caught_signal; }

 private:
   void restore() noexcept {
      while (installed_ != 0) {
         --installed_;
         static_cast<void>(
            ::sigaction(signals_[installed_], &original_[installed_], nullptr));
      }
   }

   static constexpr std::array<int, 4> signals_{SIGINT, SIGTERM, SIGHUP,
                                                SIGQUIT};
   std::array<struct sigaction, signals_.size()> original_{};
   std::size_t installed_{};
};

class TerminalEchoGuard {
 public:
   TerminalEchoGuard() {
      if (::isatty(STDIN_FILENO) != 1) {
         throw std::runtime_error{
            "passphrase input requires an interactive terminal"};
      }

      if (::tcgetattr(STDIN_FILENO, &original_) == -1) {
         throw std::system_error{errno, std::generic_category(),
                                 "could not read terminal settings"};
      }

      auto hidden = original_;
      const auto echo_flags = static_cast<tcflag_t>(ECHO | ECHONL);
      hidden.c_lflag &= static_cast<tcflag_t>(~echo_flags);

      if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == -1) {
         throw std::system_error{errno, std::generic_category(),
                                 "could not disable terminal echo"};
      }

      restore_ = true;
   }

   TerminalEchoGuard(const TerminalEchoGuard&) = delete;
   TerminalEchoGuard& operator=(const TerminalEchoGuard&) = delete;

   ~TerminalEchoGuard() {
      if (restore_) {
         static_cast<void>(::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_));
      }
   }

 private:
   termios original_{};
   bool restore_{false};
};

std::string openssl_error_message() {
   const auto error_code = ERR_get_error();

   if (error_code == 0) {
      return "OpenSSL did not provide additional error information";
   }

   std::array<char, 256> buffer{};
   ERR_error_string_n(error_code, buffer.data(), buffer.size());

   return buffer.data();
}

std::vector<std::string> load_wordlist(const std::string& filename) {
   std::ifstream file{filename};

   if (!file) {
      throw std::runtime_error{"could not open wordlist file: " + filename};
   }

   std::vector<std::string> words;
   std::string word;

   while (std::getline(file, word)) {
      // Remove a carriage return from a CRLF-formatted wordlist.
      if (!word.empty() && word.back() == '\r') {
         word.pop_back();
      }

      if (word.empty()) {
         throw std::runtime_error{"wordlist contains an empty line"};
      }

      words.push_back(std::move(word));
   }

   // Eleven bits can address exactly 2048 entries. A list of any other
   // size cannot be indexed according to BIP-39.
   if (words.size() != bip39::wordlist_size) {
      throw std::runtime_error{
         "wordlist must contain exactly 2048 words; found " +
         std::to_string(words.size())};
   }

   // Duplicate words would make the word-to-index mapping ambiguous.
   const std::unordered_set<std::string> unique_words{words.begin(),
                                                      words.end()};

   if (unique_words.size() != words.size()) {
      throw std::runtime_error{"wordlist contains duplicate words"};
   }

   // Caution:
   //
   // BIP-39 compatibility depends on both the contents and exact ordering
   // of the wordlist. A custom list preserves the underlying indices, but
   // another program must use the identical list in the identical order.
   //
   // BIP-39 also requires non-ASCII wordlists to use UTF-8 NFKD
   // normalization. This educational program does not provide Unicode
   // normalization. The official English list is ASCII and is unaffected.
   return words;
}

Bytes generate_system_entropy(std::size_t byte_count) {
   Bytes entropy(byte_count);

   // RAND_priv_bytes() obtains bytes from OpenSSL's private CSPRNG.
   //
   // On supported systems, OpenSSL seeds this generator from the operating
   // system's random facility. If secure randomness cannot be obtained, the
   // program must stop rather than substitute a weaker fallback.
   //
   // This program therefore does not:
   //
   //   * traverse or hash ordinary files;
   //   * use std::random_device;
   //   * use std::mt19937;
   //   * open /dev/random directly.
   if (RAND_priv_bytes(entropy.data(), static_cast<int>(entropy.size())) != 1) {
      throw std::runtime_error{"RAND_priv_bytes failed: " +
                               openssl_error_message()};
   }

   return entropy;
}

char read_die_face(std::size_t roll_number, std::size_t roll_count) {
   for (;;) {
      std::cout << "Roll " << roll_number << '/' << roll_count << ": "
                << std::flush;

      std::string input;
      if (!std::getline(std::cin, input)) {
         throw std::runtime_error{
            "input ended before all dice rolls were entered"};
      }

      std::istringstream stream{input};
      int roll{};
      char extra{};

      if ((stream >> roll) && !(stream >> extra) && roll >= 1 && roll <= 6) {
         return static_cast<char>('0' + roll);
      }

      std::cerr << "Please enter one die result from 1 through 6.\n";
   }
}

entropy::ZeroBasedDiceRolls read_mixed_dice_rolls(std::size_t roll_count) {
   entropy::ZeroBasedDiceRolls rolls;
   rolls.reserve(roll_count);

   for (std::size_t roll_number = 1; roll_number <= roll_count; ++roll_number) {
      const auto face = read_die_face(roll_number, roll_count);
      rolls.push_back(static_cast<unsigned char>(face - '1'));
   }

   return rolls;
}

std::string read_ascii_dice_rolls(std::size_t roll_count) {
   std::string rolls;
   rolls.reserve(roll_count);

   for (std::size_t roll_number = 1; roll_number <= roll_count; ++roll_number) {
      rolls.push_back(read_die_face(roll_number, roll_count));
   }

   return rolls;
}

Bytes generate_mixed_dice_entropy(std::size_t byte_count) {
   const auto entropy_bit_count = byte_count * 8U;
   const auto roll_count = entropy::mixed_dice_roll_count(byte_count);

   std::cout << "Dice mode requires " << roll_count << " rolls for "
             << entropy_bit_count << " bits of BIP-39 entropy.\n"
             << "Enter each die result as a number from 1 through 6.\n\n";

   const auto rolls = read_mixed_dice_rolls(roll_count);
   const auto system_random = generate_system_entropy(bip39::sha256_size);
   return entropy::mix_dice_entropy(rolls, system_random, byte_count);
}

Bytes generate_dice_only_entropy(std::size_t byte_count) {
   const auto entropy_bit_count = byte_count * 8U;
   const auto roll_count = entropy::dice_only_roll_count(byte_count);

   std::cout << "Dice-only compatibility mode requires " << roll_count
             << " rolls for " << entropy_bit_count
             << " bits of BIP-39 entropy.\n"
             << "This mode does not mix OpenSSL randomness.\n"
             << "Enter each die result as a number from 1 through 6.\n\n";

   const auto rolls = read_ascii_dice_rolls(roll_count);
   return entropy::dice_only_entropy(rolls, byte_count);
}

void print_card_entry_instructions() {
   std::cout
      << "Enter one card at a time from the top of the deck to the bottom.\n"
      << "Ranks: a, 2 through 10, j, q, k. Suits: c, d, h, s.\n"
      << "Examples: as, 10d, qh. The letter t may be used for ten.\n"
      << "Card names are case-insensitive.\n\n";
}

std::string read_card_deck(std::size_t shuffle_number) {
   std::string deck;
   deck.reserve(entropy::canonical_deck_size);

   std::unordered_set<std::string> seen;
   seen.reserve(entropy::cards_per_deck);

   for (std::size_t position = 1; position <= entropy::cards_per_deck;) {
      std::cout << "Shuffle " << shuffle_number << ", card " << position << '/'
                << entropy::cards_per_deck << ": " << std::flush;

      std::string input;
      if (!std::getline(std::cin, input)) {
         throw std::runtime_error{"input ended before all cards were entered"};
      }

      try {
         auto card = entropy::normalize_card(input);

         if (!seen.insert(card).second) {
            std::cerr << "Duplicate card: " << card
                      << ". Enter a different card.\n";
            continue;
         }

         deck += card;
         ++position;
      } catch (const std::invalid_argument& error) {
         std::cerr << error.what() << '\n';
      }
   }

   return deck;
}

Bytes generate_mixed_card_entropy(std::size_t byte_count) {
   const auto entropy_bit_count = byte_count * 8U;

   std::cout << "Cards mode requires one shuffled 52-card deck for "
             << entropy_bit_count << " bits of BIP-39 entropy.\n"
             << "This mode mixes the deck ordering with 32 bytes of OpenSSL "
                "randomness.\n";
   print_card_entry_instructions();

   const auto deck = read_card_deck(1);
   const auto system_random = generate_system_entropy(bip39::sha256_size);
   return entropy::mix_card_entropy(deck, system_random, byte_count);
}

Bytes generate_cards_only_entropy(std::size_t byte_count) {
   const auto entropy_bit_count = byte_count * 8U;
   const auto deck_count = entropy::cards_only_deck_count(byte_count);

   std::cout << "Cards-only mode requires " << deck_count
             << (deck_count == 1 ? " shuffled deck" : " independent shuffles")
             << " for " << entropy_bit_count << " bits of BIP-39 entropy.\n"
             << "This mode does not mix OpenSSL randomness.\n";
   print_card_entry_instructions();

   const auto first_deck = read_card_deck(1);

   if (deck_count == 1) {
      return entropy::cards_only_entropy(first_deck, {}, byte_count);
   }

   std::cout
      << "\nA single shuffled deck cannot supply 256 bits of card-only "
         "entropy.\n"
      << "Restore the deck to canonical order, perform a fresh shuffle,\n"
      << "then enter the second ordering from top to bottom.\n\n";

   const auto second_deck = read_card_deck(2);
   return entropy::cards_only_entropy(first_deck, second_deck, byte_count);
}

// Read one bit with the most significant bit of the first byte first.
//
// BIP-39 treats entropy and checksum as one continuous bit sequence in this
// order. This convention also matches ordinary hexadecimal display.
bool read_bit(const unsigned char* bytes, std::size_t bit_position) {
   const auto byte_position = bit_position / 8;
   const auto bit_within_byte = bit_position % 8;
   const auto shift = 7U - static_cast<unsigned int>(bit_within_byte);

   return ((bytes[byte_position] >> shift) & 1U) != 0;
}

void print_entropy_and_checksum(const Bytes& entropy, const Digest& digest) {
   // Caution:
   //
   // The entropy is secret key material. Anyone who obtains it can recreate
   // the mnemonic and any wallet derived from that mnemonic.
   //
   // This output is intended only for educational inspection and comparison
   // with BIP-39 test vectors. Terminal scrollback, logs, screenshots and
   // shell recordings may retain it.
   std::cout << "\n    BIP-39 Internals\n\n";

   std::cout << "Entropy:      ";

   for (const auto byte : entropy) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(byte);
   }

   std::cout << std::dec << std::setfill(' ') << '\n';

   const auto entropy_bit_count = entropy.size() * 8;
   const auto checksum_bit_count = entropy_bit_count / 32;

   std::cout << "Checksum:     ";

   for (std::size_t bit = 0; bit < checksum_bit_count; ++bit) {
      std::cout << (read_bit(digest.data(), bit) ? '1' : '0');
   }

   std::cout << '\n'
             << "Entropy bits: " << entropy_bit_count << '\n'
             << "Checksum bits: " << checksum_bit_count << '\n';
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

void print_mnemonic(const std::vector<std::string>& words,
                    const std::vector<std::uint16_t>& indices) {
   std::cout << "\n    Seed Words\n\n";

   for (std::size_t position = 0; position < indices.size(); ++position) {
      std::cout << std::setw(6) << (position + 1) << ") "
                << words[indices[position]] << '\n';
   }
}

void print_tiny_seed(const std::vector<std::uint16_t>& indices) {
   std::cout << "\n    Tiny Seed\n\n";

   // "Tiny Seed" is a physical representation of the BIP-39 indices.
   //
   // Each wordlist index is exactly eleven bits and is zero-based:
   //
   //   wordlist[0]    = 00000000000
   //   wordlist[2047] = 11111111111
   //
   // Do not add one before engraving or stamping. Doing so would encode a
   // different BIP-39 index.
   for (std::size_t position = 0; position < indices.size(); ++position) {
      std::cout << std::setw(6) << (position + 1) << ") ";

      const std::bitset<bip39::bits_per_word> binary{indices[position]};

      for (int bit = static_cast<int>(bip39::bits_per_word) - 1; bit >= 0;
           --bit) {
         std::cout << (binary[static_cast<std::size_t>(bit)] ? "█ " : "_ ");
      }

      std::cout << '\n';
   }
}

void read_hidden_line(std::string_view prompt, SensitiveString& text) {
   std::cout << prompt << std::flush;

   std::string input;
   int signal_number{};

   {
      SignalGuard signal_guard;
      TerminalEchoGuard echo_guard;
      std::array<char, 256> buffer{};

      for (;;) {
         const auto byte_count =
            ::read(STDIN_FILENO, buffer.data(), buffer.size());

         if (byte_count > 0) {
            input.append(buffer.data(), static_cast<std::size_t>(byte_count));

            if (!input.empty() && input.back() == '\n') {
               input.pop_back();

               if (!input.empty() && input.back() == '\r') {
                  input.pop_back();
               }

               break;
            }

            continue;
         }

         if (byte_count == 0) {
            throw std::runtime_error{"input ended while reading passphrase"};
         }

         if (errno == EINTR) {
            signal_number = signal_guard.signal_number();

            if (signal_number != 0) {
               break;
            }

            continue;
         }

         throw std::system_error{errno, std::generic_category(),
                                 "could not read passphrase"};
      }
   }

   std::cout << '\n';

   if (signal_number != 0) {
      static_cast<void>(std::raise(signal_number));
      throw std::runtime_error{"passphrase entry interrupted"};
   }

   text.value() = std::move(input);
}

void read_passphrase(SensitiveString& passphrase) {
   read_hidden_line("BIP-39 passphrase (empty for none): ", passphrase);

   if (passphrase.value().empty()) {
      return;
   }

   SensitiveString confirmation;
   read_hidden_line("Confirm passphrase: ", confirmation);

   if (passphrase.value() != confirmation.value()) {
      throw std::invalid_argument{"passphrases do not match"};
   }
}

void print_seed_derivation(std::string_view mnemonic, bool has_passphrase,
                           const Seed& seed) {
   std::cout << "\n    BIP-39 Derivation\n\n"
             << "Mnemonic:   " << mnemonic << '\n'
             << "Passphrase: "
             << (has_passphrase ? "set (not displayed)" : "empty") << '\n'
             << "Seed:       ";

   for (const auto byte : seed) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(byte);
   }

   std::cout << std::dec << std::setfill(' ') << '\n'
             << "Warning: the mnemonic and seed are secret wallet material.\n"
             << "Terminal scrollback, logs, and screenshots may retain them.\n";
}

void add_command_line_options(po::options_description& description,
                              ProgramOptions& options) {
   description.add_options()("help,h", po::bool_switch(&options.show_help),
                             "display this help and exit")(
      "wordlist,w", po::value<std::string>(&options.wordlist_filename),
      "read the BIP-39 wordlist from FILE; defaults to compiled English")(
      "words,n", po::value<std::size_t>(&options.word_count),
      "number of mnemonic words: 12, 15, 18, 21, or 24; defaults to 12")(
      "dice,d", po::bool_switch(&options.use_dice),
      "interactively mix dice rolls with OpenSSL private randomness")(
      "dice-only", po::bool_switch(&options.use_dice_only),
      "use only SHA-256 of ASCII dice rolls for compatibility")(
      "cards", po::bool_switch(&options.use_cards),
      "mix one shuffled card deck with OpenSSL private randomness")(
      "cards-only", po::bool_switch(&options.use_cards_only),
      "use only shuffled card orderings; two shuffles for 24 words")(
      "show-entropy,e", po::bool_switch(&options.show_entropy),
      "display the entropy and checksum")(
      "show-seed", po::bool_switch(&options.show_seed),
      "derive and display the BIP-39 seed; prompts for passphrase");
}

void print_help(const std::string& program_name) {
   ProgramOptions options{};
   po::options_description description{"Options"};

   add_command_line_options(description, options);

   std::cout << "Usage: " << program_name << " [options]\n\n"
             << description << '\n';
}

ProgramOptions parse_command_line(int argc, char* argv[]) {
   ProgramOptions options{};

   po::options_description description{"Options"};
   add_command_line_options(description, options);

   po::variables_map variables;
   po::store(po::parse_command_line(argc, argv, description), variables);
   po::notify(variables);

   if (!options.show_help) {
      const std::array entropy_sources{
         options.use_dice,
         options.use_dice_only,
         options.use_cards,
         options.use_cards_only,
      };

      if (std::count(entropy_sources.begin(), entropy_sources.end(), true) >
          1) {
         throw std::invalid_argument{
            "--dice, --dice-only, --cards, and --cards-only are mutually "
            "exclusive"};
      }

      static_cast<void>(
         bip39::entropy_bytes_for_word_count(options.word_count));
   }

   return options;
}

} // namespace

int main(int argc, char* argv[]) try {
   ProgramOptions options{};
   options = parse_command_line(argc, argv);

   if (options.show_help) {
      print_help(argv[0]);
      return 0;
   }

   const auto words = options.wordlist_filename.empty()
                         ? bip39::make_english_word_list()
                         : load_wordlist(options.wordlist_filename);
   const auto entropy_byte_count =
      bip39::entropy_bytes_for_word_count(options.word_count);

   // Report the random-number API path without exposing random bytes.
   Bytes entropy;

   if (options.use_cards_only) {
      std::cerr << "Entropy path: SHA-256(canonical card ordering), no system "
                   "randomness\n";

      entropy = generate_cards_only_entropy(entropy_byte_count);
   } else if (options.use_cards) {
      std::cerr
         << "Entropy path: SHA-256(card ordering || RAND_priv_bytes())\n";

      entropy = generate_mixed_card_entropy(entropy_byte_count);
   } else if (options.use_dice_only) {
      std::cerr
         << "Entropy path: SHA-256(ASCII dice rolls), no system randomness\n";

      entropy = generate_dice_only_entropy(entropy_byte_count);
   } else if (options.use_dice) {
      std::cerr << "Entropy path: SHA-256(dice rolls || RAND_priv_bytes())\n";

      entropy = generate_mixed_dice_entropy(entropy_byte_count);
   } else {
      std::cerr << "Entropy path: OpenSSL RAND_priv_bytes()"
                << " <- OpenSSL private CSPRNG"
                << " <- operating-system random generator\n";

      entropy = generate_system_entropy(entropy_byte_count);
   }

   const auto digest = bip39::sha256(entropy);
   const auto indices =
      bip39::make_indices(entropy, digest, options.word_count);
   const auto mnemonic = make_mnemonic(words, indices);

   if (options.show_entropy) {
      print_entropy_and_checksum(entropy, digest);
   }

   print_mnemonic(words, indices);
   print_tiny_seed(indices);

   if (options.show_seed) {
      SensitiveString passphrase;
      read_passphrase(passphrase);

      auto seed = bip39::derive_seed(mnemonic, passphrase.value());
      print_seed_derivation(mnemonic, !passphrase.value().empty(), seed);
      OPENSSL_cleanse(seed.data(), seed.size());
   }

   std::cout << '\n';

   // Security caution:
   //
   // The mnemonic itself is secret key material. Terminal output may be
   // retained in scrollback, logs, backups, screenshots or remote-session
   // history. Real wallet material should be generated only on a suitably
   // trusted and preferably offline system.
   return 0;
} catch (const std::exception& error) {
   std::cerr << "Error: " << error.what() << '\n';
   return 1;
}

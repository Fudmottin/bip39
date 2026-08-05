#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <boost/program_options.hpp>

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

std::vector<std::string> make_english_word_list();

namespace {

// BIP-39 word lists contain exactly 2^11 entries. Each mnemonic word
// therefore represents one 11-bit, zero-based index.
constexpr std::size_t bip39_wordlist_size{2048};
constexpr std::size_t bits_per_word{11};
constexpr std::size_t sha256_size{32};

using Bytes = std::vector<unsigned char>;
using Digest = std::array<unsigned char, sha256_size>;

namespace po = boost::program_options;

struct ProgramOptions {
   ProgramOptions()
      : wordlist_filename{},
        word_count{12},
        show_entropy{false},
        show_help{false} {}

   std::string wordlist_filename;
   std::size_t word_count;
   bool show_entropy;
   bool show_help;
};

// BIP-39 permits only these mnemonic lengths:
//
//   12 words -> 128 entropy bits + 4 checksum bits
//   15 words -> 160 entropy bits + 5 checksum bits
//   18 words -> 192 entropy bits + 6 checksum bits
//   21 words -> 224 entropy bits + 7 checksum bits
//   24 words -> 256 entropy bits + 8 checksum bits
//
// The initial entropy length is called ENT in BIP-39.
std::size_t entropy_bytes_for_word_count(std::size_t word_count) {
   switch (word_count) {
   case 12:
      return 16;
   case 15:
      return 20;
   case 18:
      return 24;
   case 21:
      return 28;
   case 24:
      return 32;
   default:
      throw std::invalid_argument{"word count must be 12, 15, 18, 21, or 24"};
   }
}

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
   if (words.size() != bip39_wordlist_size) {
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

Bytes generate_entropy(std::size_t byte_count) {
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

Digest sha256(const Bytes& data) {
   Digest digest{};
   unsigned int digest_length{};

   // BIP-39 computes SHA-256 over the original entropy. The first ENT / 32
   // bits of this digest become the mnemonic checksum.
   if (EVP_Digest(data.data(), data.size(), digest.data(), &digest_length,
                  EVP_sha256(), nullptr) != 1) {
      throw std::runtime_error{"SHA-256 failed: " + openssl_error_message()};
   }

   if (digest_length != digest.size()) {
      throw std::runtime_error{"SHA-256 returned an unexpected length"};
   }

   return digest;
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

std::vector<std::uint16_t> make_indices(const Bytes& entropy,
                                        const Digest& digest,
                                        std::size_t word_count) {
   const auto entropy_bit_count = entropy.size() * 8;

   // BIP-39 defines:
   //
   //   CS = ENT / 32
   //
   // ENT + CS is then divided into 11-bit groups.
   const auto checksum_bit_count = entropy_bit_count / 32;
   const auto combined_bit_count = entropy_bit_count + checksum_bit_count;

   if (combined_bit_count != word_count * bits_per_word) {
      throw std::logic_error{
         "internal BIP-39 entropy-length calculation failed"};
   }

   std::vector<std::uint16_t> indices;
   indices.reserve(word_count);

   for (std::size_t word_number = 0; word_number < word_count; ++word_number) {
      std::uint16_t index{};

      // Each word index is formed from eleven consecutive bits.
      //
      // Different groups may produce the same index. Repeated words are
      // therefore valid BIP-39 output and must not be removed.
      for (std::size_t bit = 0; bit < bits_per_word; ++bit) {
         const auto combined_position = word_number * bits_per_word + bit;

         bool value{};

         if (combined_position < entropy_bit_count) {
            value = read_bit(entropy.data(), combined_position);
         } else {
            const auto checksum_position =
               combined_position - entropy_bit_count;

            value = read_bit(digest.data(), checksum_position);
         }

         index = static_cast<std::uint16_t>((index << 1U) |
                                            static_cast<std::uint16_t>(value));
      }

      // Eleven bits can only produce values from 0 through 2047.
      if (index >= bip39_wordlist_size) {
         throw std::logic_error{
            "generated index is outside the BIP-39 wordlist"};
      }

      indices.push_back(index);
   }

   return indices;
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

      const std::bitset<bits_per_word> binary{indices[position]};

      for (int bit = static_cast<int>(bits_per_word) - 1; bit >= 0; --bit) {
         std::cout << (binary[static_cast<std::size_t>(bit)] ? "█ " : "_ ");
      }

      std::cout << '\n';
   }
}

void add_command_line_options(po::options_description& description,
                              ProgramOptions& options) {
   description.add_options()
      ("help,h",
       po::bool_switch(&options.show_help),
       "display this help and exit")
      ("wordlist,w",
       po::value<std::string>(&options.wordlist_filename),
       "read the BIP-39 wordlist from FILE; defaults to compiled English")
      ("words,n",
       po::value<std::size_t>(&options.word_count),
       "number of mnemonic words: 12, 15, 18, 21, or 24; defaults to 12")
      ("show-entropy,e",
       po::bool_switch(&options.show_entropy),
       "display the entropy and checksum");
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
      static_cast<void>(
         entropy_bytes_for_word_count(options.word_count));
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
                         ? make_english_word_list()
                         : load_wordlist(options.wordlist_filename);
   const auto entropy_byte_count =
      entropy_bytes_for_word_count(options.word_count);

   // Report the random-number API path without exposing random bytes.
   std::cerr << "Entropy path: OpenSSL RAND_priv_bytes()"
             << " <- OpenSSL private CSPRNG"
             << " <- operating-system random generator\n";

   const auto entropy = generate_entropy(entropy_byte_count);
   const auto digest = sha256(entropy);
   const auto indices = make_indices(entropy, digest, options.word_count);

   if (options.show_entropy) {
      print_entropy_and_checksum(entropy, digest);
   }

   print_mnemonic(words, indices);
   print_tiny_seed(indices);

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


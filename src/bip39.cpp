// src/bip39.cpp

#include "bip39.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// english_words.cpp currently provides this generated data function in the
// global namespace. Keep that implementation unchanged while presenting a
// namespaced public interface from bip39.hpp.
std::vector<std::string> make_english_word_list();

namespace bip39 {
namespace {

constexpr int pbkdf2_iterations{2048};

std::string openssl_error_message() {
   const auto error_code = ERR_get_error();

   if (error_code == 0) {
      return "OpenSSL did not provide additional error information";
   }

   std::array<char, 256> buffer{};
   ERR_error_string_n(error_code, buffer.data(), buffer.size());

   return buffer.data();
}

int checked_int(std::size_t size) {
   constexpr auto maximum =
      static_cast<std::size_t>(std::numeric_limits<int>::max());

   if (size > maximum) {
      throw std::length_error{"BIP-39 input is too large"};
   }

   return static_cast<int>(size);
}

void require_ascii(std::string_view text, std::string_view description) {
   const auto is_ascii = [](char character) {
      return static_cast<unsigned char>(character) <= 0x7fU;
   };

   if (!std::all_of(text.begin(), text.end(), is_ascii)) {
      throw std::invalid_argument{std::string{description} +
                                  " must contain ASCII characters only"};
   }
}

// Read one bit with the most significant bit of the first byte first.
// BIP-39 treats entropy and checksum as one continuous bit sequence.
bool read_bit(const unsigned char* bytes, std::size_t bit_position) {
   const auto byte_position = bit_position / 8;
   const auto bit_within_byte = bit_position % 8;
   const auto shift = 7U - static_cast<unsigned int>(bit_within_byte);

   return ((bytes[byte_position] >> shift) & 1U) != 0;
}

} // namespace

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

std::vector<std::uint16_t> make_indices(const Bytes& entropy,
                                        const Digest& digest,
                                        std::size_t word_count) {
   const auto expected_entropy_byte_count =
      entropy_bytes_for_word_count(word_count);

   if (entropy.size() != expected_entropy_byte_count) {
      throw std::invalid_argument{"entropy size does not match word count"};
   }

   const auto entropy_bit_count = entropy.size() * 8;

   // BIP-39 defines CS = ENT / 32. ENT + CS is divided into 11-bit groups.
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

      // Each word index is formed from eleven consecutive bits. Repeated
      // indices are valid and must not be removed.
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
      if (index >= wordlist_size) {
         throw std::logic_error{
            "generated index is outside the BIP-39 wordlist"};
      }

      indices.push_back(index);
   }

   return indices;
}

Seed derive_seed(std::string_view mnemonic, std::string_view passphrase) {
   require_ascii(mnemonic, "mnemonic");
   require_ascii(passphrase, "passphrase");

   std::string salt{"mnemonic"};
   salt.append(passphrase.begin(), passphrase.end());

   Seed seed{};
   const auto* password = mnemonic.empty() ? "" : mnemonic.data();

   if (PKCS5_PBKDF2_HMAC(password, checked_int(mnemonic.size()),
                         reinterpret_cast<const unsigned char*>(salt.data()),
                         checked_int(salt.size()), pbkdf2_iterations,
                         EVP_sha512(), checked_int(seed.size()),
                         seed.data()) != 1) {
      throw std::runtime_error{"PBKDF2-HMAC-SHA512 failed: " +
                               openssl_error_message()};
   }

   return seed;
}

std::vector<std::string> make_english_word_list() {
   return ::make_english_word_list();
}

} // namespace bip39


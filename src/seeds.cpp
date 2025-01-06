#include <algorithm>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <random>
#include <string>
#include <vector>
#include <bitset>
#include <ranges>
#include <filesystem>
#include <functional>
#include <optional>

void print_usage(const std::string& program_name) {
    std::cerr << "Usage: " << program_name << " <BIP-39-word-file> <count>\n";
}

std::size_t generate_entropy_from_files(std::mt19937& gen) {
    namespace fs = std::filesystem;
    std::size_t entropy = 0;
    std::vector<fs::path> files;

    // Traverse the filesystem recursively and collect readable files
    try {
        for (const auto& entry : fs::recursive_directory_iterator(fs::path("/"))) {
            if (entry.is_regular_file() && (fs::status(entry.path()).permissions() & fs::perms::owner_read) != fs::perms::none) {
                files.push_back(entry.path());
            }
        }
    } catch (...) {
        // Handle any errors that might occur during directory iteration (e.g., permission errors)
        std::cerr << "Error during filesystem traversal.\n";
    }

    if (files.empty()) {
        return entropy; // No files found
    }

    // Shuffle file list and pick a random subset
    std::shuffle(files.begin(), files.end(), gen);
    size_t num_files = std::uniform_int_distribution<size_t>(1, std::min<size_t>(5, files.size()))(gen);

    for (size_t i = 0; i < num_files; ++i) {
        std::ifstream file(files[i], std::ios::binary);
        if (!file) continue;

        // Read some bytes directly from the file (no seeking to a random offset)
        char buffer[256];
        file.read(buffer, sizeof(buffer));
        std::string data(buffer, file.gcount());

        // Combine entropy by XORing the hash of the file data
        entropy ^= std::hash<std::string>{}(data);
    }

    return entropy;
}

std::optional<std::size_t> generate_entropy_from_hardware() {
    std::ifstream dev_random("/dev/random", std::ios::binary);
    if (dev_random) {
        std::size_t entropy = 0;
        dev_random.read(reinterpret_cast<char*>(&entropy), sizeof(entropy));
        return entropy;
    }
    return std::nullopt;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string filename = argv[1];
    int count = 0;
    try {
        count = std::stoi(argv[2]);
    } catch (...) {
        print_usage(argv[0]);
        return 1;
    }

    if (count <= 0) {
        std::cerr << "Error: Seed count must be positive.\n";
        return 1;
    }

    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << "\n";
        return 1;
    }

    std::vector<std::string> words;
    std::string word;

    while (std::getline(file, word)) {
        if (!word.empty()) {
            words.push_back(word);
        }
    }

    if (words.size() < static_cast<size_t>(count)) {
        std::cerr << "Error: Not enough words in the file to pick " << count << " unique words\n";
        return 1;
    }

    // Initialize random generator
    std::random_device rd;
    std::mt19937 gen(rd());
    auto seed = generate_entropy_from_hardware();

    if (!seed) seed = generate_entropy_from_files(gen);
    if (seed) gen.seed(*seed);
    else gen.seed(rd());

    // Create a shuffled range of indices
    std::vector<int> range(words.size());
    std::iota(range.begin(), range.end(), 0);  // Fill with 0, 1, 2, ..., words.size()-1
    std::shuffle(range.begin(), range.end(), gen);  // Shuffle once

    std::cout << "\n    Seed Words\n\n";

    // Loop to produce words
    for (int j = 0; j < count; ++j) {
        std::cout << std::setw(6) << std::setfill(' ') << (j + 1) << ") " << words[range[j]] << "\n";
    }

    std::cout << "\n    Tiny Seed\n\n";

    // Loop to produce binary representation
    for (int j = 0; j < count; ++j) {
        std::cout << std::setw(6) << std::setfill(' ') << (j + 1) << ") ";
        // Get the binary representation of the 1-based index (range[j] + 1)
        std::bitset<12> binary(range[j] + 1); 

        // Print each bit with the custom formatting
        for (int i = 11; i >= 0; --i) {  // Loop over bits from left to right
            std::cout << (binary[i] ? "█ " : "_ ");  // "█" for 1, "_" for 0
        }
        std::cout << "\n";
    }
    std::cout << "\n\n";

    return 0;
}


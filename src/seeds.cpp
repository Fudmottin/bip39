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

namespace fs = std::filesystem;

void print_usage(const std::string& program_name) {
    std::cerr << "Usage: " << program_name << " <file> <count> [<extra-seed>]\n";
}

std::size_t generate_entropy_from_files(std::mt19937& gen) {
    std::size_t entropy = 0;
    std::vector<fs::path> files;

    // Collect files from the current directory
    try {
        for (const auto& entry : fs::directory_iterator(fs::current_path())) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path());
            }
        }
    } catch (...) {
        // Ignore errors while collecting files
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

        // Seek to a random offset
        file.seekg(0, std::ios::end);
        std::streamoff file_size = file.tellg();
        if (file_size > 0) {
            std::streamoff offset = std::uniform_int_distribution<std::streamoff>(0, file_size - 1)(gen);
            file.seekg(offset);
        }

        // Read some bytes and hash
        char buffer[256];
        file.read(buffer, sizeof(buffer));
        std::string data(buffer, file.gcount());
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

    std::string extra_seed = (argc == 4) ? argv[3] : "";

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

    // Combine file-based entropy
    std::size_t seed = generate_entropy_from_files(gen);

    // Combine hardware-based entropy
    if (auto hw_entropy = generate_entropy_from_hardware()) {
        seed ^= *hw_entropy;
    }

    // Combine user-provided seed
    if (!extra_seed.empty()) {
        seed ^= std::hash<std::string>{}(extra_seed);
    }

    gen.seed(seed);

    // Create and shuffle range
    std::uniform_int_distribution<> dist(0, words.size() - 1);
    std::vector<int> range(count);
    std::generate(range.begin(), range.end(), [&]() { return dist(gen); });

    // Loop to produce words
    int j = 1;
    std::cout << "\n    Seed Words\n\n";
    for (int i : range) {
        std::cout << std::setw(6) << std::setfill(' ') << j << ") " << words[i] << "\n";
        if (++j > count) break;
    }

    std::cout << "\n    Tiny Seed" << "\n\n";

    // Loop to produce binary representation
    j = 1;
    for (int i : range) {
        std::cout << "    ";
        std::bitset<12> binary(i + 1); // Assuming 12-bit representation
        for (int j = 11; j >= 0; --j) { // This j should shadow the outer j
            std::cout << (binary[j] ? 'X' : '.');
        }
        std::cout << "\n";
        if (++j > count) break; // This should be the outer j
    }
    std::cout << "\n\n";

    return 0;
}


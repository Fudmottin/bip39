add_executable(
   bip39_tests
   test.cpp
)

target_link_libraries(
   bip39_tests
   PRIVATE
      bip39_core
)

add_test(
   NAME bip39.vectors
   COMMAND bip39_tests
)


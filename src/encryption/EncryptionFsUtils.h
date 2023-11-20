#ifndef ENCRYPTION_FS_UTILS_HPP
#define ENCRYPTION_FS_UTILS_HPP

#include "KeyPairTxRx.hpp"
#include <string>

namespace wb {

/**
 * Saves the KeyPairTxRx as a raw file
 */
int write_keypair_to_file(const KeyPairTxRx& keypair_txrx,
                          const std::string& filename);

/**
 * Reads a raw KeyPairTxRx from a raw file previusly generated.
 */
KeyPairTxRx read_keypair_from_file(const std::string& filename);

} // namespace wb end

#endif  // ENCRYPTION_FS_UTILS_HPP
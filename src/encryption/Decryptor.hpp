#ifndef DECRIPTOR_HPP
#define DECRIPTOR_HPP
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "Key.hpp"


namespace wb {
class Decryptor {
 public:
  // enable a default deterministic encryption key by using std::nullopt
  // else, pass path to file with encryption keys
  explicit Decryptor(wb::Key key1);
  static constexpr auto SESSION_VALID_NEW = 0;
  static constexpr auto SESSION_VALID_NOT_NEW = 1;
  static constexpr auto SESSION_NOT_VALID = -1;
  /**
   * Returns 0 if the session is a valid session in regards to the key-pairs AND
   * the session is a new session Returns 1 if the session is a valid session in
   * regards to the key-pairs but it is not a new session Returns -1 if the
   * session is not a valid session in regards to the key-pairs
   *
   */
  int onNewPacketSessionKeyData(
      const std::array<uint8_t, crypto_box_NONCEBYTES>& sessionKeyNonce,
      const std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES +
                                    crypto_box_MACBYTES>& sessionKeyData);
  /**
   * Decrypt (or validate only if encryption is disabled) the given message
   * and writes the original message content into dest.
   * Returns true on success, false otherwise (false== the message is not a
   * valid message)
   * @param dest needs to be at least @param encrypted - 16 bytes big.
   */
  bool authenticate_and_decrypt(const uint64_t& nonce, const uint8_t* encrypted,
                                int encrypted_size, uint8_t* dest);

  /**
   * Easier to use, but usage might require memcpy
   */
  std::shared_ptr<std::vector<uint8_t>> authenticate_and_decrypt_buff(
      const uint64_t& nonce, const uint8_t* encrypted, int encrypted_size);
  /**
   * Disables encryption (to save cpu performance) but keeps packet validation
   * functionality
   * @param encryption_enabled
   */
  void set_encryption_enabled(bool encryption_enabled) {
    m_encrypt_data = encryption_enabled;
  }
  // Set to true as soon as a valid session has been detected
  bool has_valid_session() const { return m_has_valid_session; }

 private:
  // use this one if you are worried about CPU usage when using encryption
  bool m_encrypt_data = true;
  const std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
  const std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
  bool m_has_valid_session = false;
};

}  // namespace wb

#endif  // DECRIPTOR_HPP
#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/dsa.h"
#include "crypto++/osrng.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/hkdf.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>
#include <crypto++/sha.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/ot_driver.hpp"

/*
 * Constructor
 */
OTDriver::OTDriver(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->AES_key = keys.first;
  this->HMAC_key = keys.second;
  this->cli_driver = std::make_shared<CLIDriver>();
}

/*
 * Send either m0 or m1 using OT. This function should:
 * 1) Sample a public DH value and send it to the receiver
 * 2) Receive the receiver's public value
 * 3) Encrypt m0 and m1 using different keys
 * 4) Send the encrypted values
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
void OTDriver::OT_send(std::string m0, std::string m1)
{
  // Sample a public DH value and send it to the receiver
  // Outputs of dh_initialize() are a (private key) and g^a (public key)
  this->cli_driver->print_left("In OT_Send");
  SenderToReceiver_OTPublicValue_Message OT_pub_val_msg;
  auto [dh_obj, a, g_to_a] = this->crypto_driver->DH_initialize();
  this->cli_driver->print_left("after DH_initialize");
  OT_pub_val_msg.public_value = g_to_a;
  auto OT_pub_val_msg_bytes = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &OT_pub_val_msg);
  this->cli_driver->print_left("before send, after encrypt and tag");
  this->network_driver->send(OT_pub_val_msg_bytes);
  this->cli_driver->print_left("finished sampling public DH value");

  // Receive the receiver's public value
  auto receiver_to_sender_msg_data = this->network_driver->read();
  ReceiverToSender_OTPublicValue_Message receiver_to_sender_OT_pub_msg;
  auto [decrypted_receiver_to_sender_data, receiver_to_sender_msg_decrypted] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, receiver_to_sender_msg_data);
  if (!receiver_to_sender_msg_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the receiver to sender OT message");
  }
  receiver_to_sender_OT_pub_msg.deserialize(decrypted_receiver_to_sender_data);
  this->cli_driver->print_left("receive the receiver's public value");

  // Encrypt m0 using key created via AES_generate_key and DH_generate_shared_key
  auto shared_key_m0 = this->crypto_driver->DH_generate_shared_key(dh_obj, a, receiver_to_sender_OT_pub_msg.public_value);
  this->cli_driver->print_left("after DH_generate_key");
  auto k0 = this->crypto_driver->AES_generate_key(shared_key_m0);
  this->cli_driver->print_left("after AES_generate_key");
  auto [e0, iv0] = this->crypto_driver->AES_encrypt(k0, m0);
  this->cli_driver->print_left("after AES_encrypt");
  this->cli_driver->print_left("finished encrypting m0");

  // Encrypt m1 using key created via AES_generate_key and DH_generate_shared_key
  auto A_inverse = CryptoPP::EuclideanMultiplicativeInverse(byteblock_to_integer(g_to_a), DL_P);
  auto b_times_A_inverse = a_times_b_mod_c(byteblock_to_integer(receiver_to_sender_OT_pub_msg.public_value), A_inverse, DL_P);
  auto shared_key_m1 = this->crypto_driver->DH_generate_shared_key(dh_obj, a, integer_to_byteblock(b_times_A_inverse));
  auto k1 = this->crypto_driver->AES_generate_key(shared_key_m1);
  auto [e1, iv1] = this->crypto_driver->AES_encrypt(k1, m1);
  this->cli_driver->print_left("finished encrypting m1");

  // Send the encrypted values
  SenderToReceiver_OTEncryptedValues_Message sender_to_receiver_ot_encrypted_vals_msg;
  sender_to_receiver_ot_encrypted_vals_msg.e0 = e0;
  sender_to_receiver_ot_encrypted_vals_msg.e1 = e1;
  sender_to_receiver_ot_encrypted_vals_msg.iv0 = iv0;
  sender_to_receiver_ot_encrypted_vals_msg.iv1 = iv1;
  auto OT_encrypted_vals_msg_bytes = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &sender_to_receiver_ot_encrypted_vals_msg);
  this->network_driver->send(OT_encrypted_vals_msg_bytes);
  this->cli_driver->print_left("finished sending encrypted values");
}

/*
 * Receive m_c using OT. This function should:
 * 1) Read the sender's public value
 * 2) Respond with our public value that depends on our choice bit
 * 3) Generate the appropriate key and decrypt the appropriate ciphertext
 * You may find `byteblock_to_integer` and `integer_to_byteblock` useful
 * Disconnect and throw errors only for invalid MACs
 */
std::string OTDriver::OT_recv(int choice_bit)
{
  // Read the sender's public value (A = g^a)
  auto sender_to_receiver_msg_data = this->network_driver->read();
  SenderToReceiver_OTPublicValue_Message sender_to_receiver_OT_msg;
  auto [decrypted_sender_to_receiver_data, sender_to_receiver_msg_decrypted] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, sender_to_receiver_msg_data);
  if (!sender_to_receiver_msg_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the receiver to sender OT message");
  }
  sender_to_receiver_OT_msg.deserialize(decrypted_sender_to_receiver_data);
  this->cli_driver->print_left("just read the sender's public value");

  // Respond with our public value that depends on our choice bit
  ReceiverToSender_OTPublicValue_Message receiver_to_sender_OT_pub_msg;
  auto [dh_obj, b, g_to_b] = this->crypto_driver->DH_initialize();
  auto A = byteblock_to_integer(sender_to_receiver_OT_msg.public_value);
  if (choice_bit == 1)
  {
    receiver_to_sender_OT_pub_msg.public_value = integer_to_byteblock(a_times_b_mod_c(A, byteblock_to_integer(g_to_b), DL_P));
  }
  else
  {
    receiver_to_sender_OT_pub_msg.public_value = g_to_b;
  }
  auto receiver_to_sender_OT_pub_val_bytes = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &receiver_to_sender_OT_pub_msg);
  this->network_driver->send(receiver_to_sender_OT_pub_val_bytes);
  this->cli_driver->print_left("just sent the receiver's public value");

  // Generate the appropriate key (kc = KDF(A^b))
  auto shared_key = this->crypto_driver->DH_generate_shared_key(dh_obj, b, integer_to_byteblock(A));
  auto aes_shared_key = this->crypto_driver->AES_generate_key(shared_key);
  this->cli_driver->print_left("generated the appropriate key");

  // Receive encrypted values from sender
  auto sender_to_receiver_encrypted_vals_msg_data = this->network_driver->read();
  SenderToReceiver_OTEncryptedValues_Message sender_to_receiver_encrypted_vals_msg;
  auto [decrypted_sender_to_receiver_encrypted_msg_data, sender_to_receiver_encrypted_vals_decrypted] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, sender_to_receiver_encrypted_vals_msg_data);
  if (!sender_to_receiver_encrypted_vals_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the receiver to sender OT message");
  }
  sender_to_receiver_encrypted_vals_msg.deserialize(decrypted_sender_to_receiver_encrypted_msg_data);
  this->cli_driver->print_left("received encrypted values from sender");

  // Decrypt the appropriate ciphertext
  std::string decryption;
  if (choice_bit == 1)
  {
    decryption = this->crypto_driver->AES_decrypt(aes_shared_key, sender_to_receiver_encrypted_vals_msg.iv1, sender_to_receiver_encrypted_vals_msg.e1);
  }
  else
  {
    decryption = this->crypto_driver->AES_decrypt(aes_shared_key, sender_to_receiver_encrypted_vals_msg.iv0, sender_to_receiver_encrypted_vals_msg.e0);
  }
  this->cli_driver->print_left("finished OT receive decryption");
  return decryption;
}
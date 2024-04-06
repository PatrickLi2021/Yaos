#include <algorithm>
#include <crypto++/misc.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/pkg/garbler.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace
{
  src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor. Note that the OT_driver is left uninitialized.
 */
GarblerClient::GarblerClient(Circuit circuit,
                             std::shared_ptr<NetworkDriver> network_driver,
                             std::shared_ptr<CryptoDriver> crypto_driver)
{
  this->circuit = circuit;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  initLogger(logging::trivial::severity_level::trace);
}

/**
 * Handle key exchange with evaluator
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
GarblerClient::HandleKeyExchange()
{
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^b
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> garbler_public_value_data;
  garbler_public_value_s.serialize(garbler_public_value_data);
  network_driver->send(garbler_public_value_data);

  // Listen for g^a
  std::vector<unsigned char> evaluator_public_value_data =
      network_driver->read();
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.deserialize(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      evaluator_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(DH_shared_key);
  auto keys = std::make_pair(AES_key, HMAC_key);
  this->ot_driver =
      std::make_shared<OTDriver>(network_driver, crypto_driver, keys);
  return keys;
}

/**
 * run. This function should:
 * 1) Generate a garbled circuit from the given circuit in this->circuit
 * 2) Send the garbled circuit to the evaluator
 * 3) Send garbler's input labels to the evaluator
 * 4) Send evaluator's input labels using OT
 * 5) Receive final labels, and use this to get the final output
 * `input` is the garbler's input for each gate
 * Final output should be a string containing only "0"s or "1"s
 * Throw errors only for invalid MACs
 */
std::string GarblerClient::run(std::vector<int> input)
{
  // // Key exchange
  // auto keys = this->HandleKeyExchange();

  // // Generate a garbled circuit from the given circuit in this->circuit
  // GarbledLabels labels = generate_labels(this->circuit);
  // Circuit garbled_circuit = generate_gates(this->circuit, labels);

  // // Send the garbled circuit to the evaluator
  // GarblerToEvaluator_GarbledTables_Message garbler_to_eval_circuit_msg;
  // garbler_to_eval_circuit_msg.garbled_tables = garbled_circuit.gates;
  // auto garbler_to_eval_circuit_msg_bytes = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &garbler_to_eval_circuit_msg);
  // this->network_driver->send(garbler_to_eval_circuit_msg_bytes);

  // // Send the garbler's input labels to the evaluator
  // GarblerToEvaluator_GarblerInputs_Message garbler_to_eval_input_labels_msg;
  // garbler_input_labels_msg.garbler_inputs = get_garbled_wires(labels, input, 0);
  // auto garbler_to_eval_input_labels_msg_bytes = this->crypto_driver->encrypt_and_tag(this->AES_key, this->HMAC_key, &garbler_to_eval_input_labels_msg);
  // this->network_driver->send(garbler_to_eval_input_labels_msg_bytes);

  // // Send evaluator's input labels using OT (call OT_send, once for each wire)
  // for (int i = garbled_circuit.garbled_input_length; i < garbled_circuit.garbled_input_length + garbled_circuit.evaluator_input_length; ++i)
  // {
  //   auto m0 = labels.zeros[i];
  //   auto m1 = labels.ones[i];
  //   this->ot_driver->OT_send(m0, m1);
  // }

  // // Receive final labels, and use this to get the final output
  // auto eval_to_garbler_final_labels_msg_data = this->network_driver->read();
  // EvaluatorToGarbler_FinalLabels_Message eval_to_garbler_final_labels_msg;
  // auto [decrypted_eval_to_garbler_final_labels_msg_data, eval_to_garbler_final_labels_msg_decrypted] = this->crypto_driver->decrypt_and_verify(this->AES_key, this->HMAC_key, eval_to_garbler_final_labels_msg);
  // if (!eval_to_garbler_final_labels_msg_decrypted)
  // {
  //   this->network_driver->disconnect();
  //   throw std::runtime_error("Could not decrypt the evaluator's final labels message");
  // }
  // eval_to_garbler_final_labels_msg.deserialize(decrypted_eval_to_garbler_final_labels_msg_data);

  // auto final_labels = eval_to_garbler_final_labels_msg.final_labels;

  // // Iterate through labels of final wires
  // std::string output_string;
  // // length of zeros, ones, and final_labels vectors is num_wire
  // for (int i = garbled_circuit.num_wire - ; i < final_labels.size(); ++i)
  // {
  //   if (final_labels[i] == labels.ones[i])
  //   {
  //     output_string += "1";
  //   }
  //   else
  //   {
  //     output_string += "0";
  //   }
  // }
  // return output_string;
}

/**
 * Generate garbled gates for the circuit by encrypting each entry.
 * You may find `std::random_shuffle` useful
 */
std::vector<GarbledGate> GarblerClient::generate_gates(Circuit circuit,
                                                       GarbledLabels labels)
{
  std::vector<GarbledGate> garbled_gates;
  for (int i = 0; i < circuit.num_gate; ++i)
  {
    auto current_gate = circuit.gates[i];
    GarbledGate new_gate;

    // Produce 4 different ciphertexts per AND/XOR gate
    if (current_gate.type == GateType::T::AND_GATE)
    {
      auto ciphertext_1 = encrypt_label(labels.zeros[current_gate.lhs], labels.zeros[current_gate.rhs], labels.zeros[current_gate.output]);
      auto ciphertext_2 = encrypt_label(labels.zeros[current_gate.lhs], labels.ones[current_gate.rhs], labels.zeros[current_gate.output]);
      auto ciphertext_3 = encrypt_label(labels.ones[current_gate.lhs], labels.zeros[current_gate.rhs], labels.zeros[current_gate.output]);
      auto ciphertext_4 = encrypt_label(labels.ones[current_gate.lhs], labels.ones[current_gate.rhs], labels.ones[current_gate.output]);

      // Add ciphertext entries to the new gate and randomly shuffle the entries
      new_gate.entries.push_back(ciphertext_1);
      new_gate.entries.push_back(ciphertext_2);
      new_gate.entries.push_back(ciphertext_3);
      new_gate.entries.push_back(ciphertext_4);
    }
    else if (current_gate.type == GateType::T::XOR_GATE)
    {
      // Calculate ciphertexts
      auto ciphertext_1 = encrypt_label(labels.zeros[current_gate.lhs], labels.zeros[current_gate.rhs], labels.zeros[current_gate.output]);
      auto ciphertext_2 = encrypt_label(labels.zeros[current_gate.lhs], labels.ones[current_gate.rhs], labels.ones[current_gate.output]);
      auto ciphertext_3 = encrypt_label(labels.ones[current_gate.lhs], labels.zeros[current_gate.rhs], labels.ones[current_gate.output]);
      auto ciphertext_4 = encrypt_label(labels.ones[current_gate.lhs], labels.ones[current_gate.rhs], labels.zeros[current_gate.output]);

      // Add ciphertext entries to the new gate and randomly shuffle the entries
      new_gate.entries.push_back(ciphertext_1);
      new_gate.entries.push_back(ciphertext_2);
      new_gate.entries.push_back(ciphertext_3);
      new_gate.entries.push_back(ciphertext_4);
    }
    else
    {
      GarbledWire dummy_wire;
      dummy_wire.value = DUMMY_RHS;

      // Calculate c(0, DUMMY)
      auto ciphertext_1 = encrypt_label(labels.zeros[current_gate.lhs], dummy_wire, labels.ones[current_gate.output]);
      auto ciphertext_2 = encrypt_label(labels.ones[current_gate.lhs], dummy_wire, labels.zeros[current_gate.output]);

      new_gate.entries.push_back(ciphertext_1);
      new_gate.entries.push_back(ciphertext_2);
    }
    std::random_shuffle(new_gate.entries.begin(), new_gate.entries.end());
    garbled_gates.push_back(new_gate);
  }
  return garbled_gates;
}

/**
 * Generate labels for *every* wire in the circuit.
 * To generate an individual label, use `generate_label`.
 */
GarbledLabels GarblerClient::generate_labels(Circuit circuit)
{
  GarbledLabels garbled_labels;
  std::vector<GarbledWire> zeros;
  std::vector<GarbledWire> ones;
  for (int i = 0; i < circuit.num_wire; ++i)
  {
    GarbledWire wire_0;
    wire_0.value = generate_label();
    GarbledWire wire_1;
    wire_1.value = generate_label();
    zeros.push_back(wire_0);
    ones.push_back(wire_1);
  }
  garbled_labels.zeros = zeros;
  garbled_labels.ones = ones;
  return garbled_labels;
}

/**
 * Generate the encrypted label given the lhs, rhs, and output of that gate.
 * Remember to tag LABEL_TAG_LENGTH trailing 0s to end before encrypting.
 * You may find CryptoDriver::hash_inputs, CryptoPP::SecByteBlock::CleanGrow,
 * and CryptoPP::xorbuf useful.
 */
CryptoPP::SecByteBlock GarblerClient::encrypt_label(GarbledWire lhs,
                                                    GarbledWire rhs,
                                                    GarbledWire output)
{
  auto encryption_1 = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
  auto encryption_2 = output.value;
  encryption_2.CleanGrow(LABEL_TAG_LENGTH * 2);
  xorbuf(encryption_1, encryption_2, LABEL_TAG_LENGTH * 2);
  return encryption_1;
}

/**
 * Generate label.
 */
CryptoPP::SecByteBlock GarblerClient::generate_label()
{
  CryptoPP::SecByteBlock label(LABEL_LENGTH);
  CryptoPP::OS_GenerateRandomBlock(false, label, label.size());
  return label;
}

/*
 * Given a set of 0/1 labels and an input vector of 0's and 1's, returns the
 * labels corresponding to the inputs starting at begin.
 */
std::vector<GarbledWire>
GarblerClient::get_garbled_wires(GarbledLabels labels, std::vector<int> input,
                                 int begin)
{
  std::vector<GarbledWire> res;
  for (int i = 0; i < input.size(); i++)
  {
    switch (input[i])
    {
    case 0:
      res.push_back(labels.zeros[begin + i]);
      break;
    case 1:
      res.push_back(labels.ones[begin + i]);
      break;
    default:
      std::cerr << "INVALID INPUT CHARACTER" << std::endl;
    }
  }
  return res;
}

#include "../../include/pkg/evaluator.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"

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
EvaluatorClient::EvaluatorClient(Circuit circuit,
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
EvaluatorClient::HandleKeyExchange()
{
  // Generate private/public DH keys
  auto dh_values = this->crypto_driver->DH_initialize();

  // Listen for g^b
  std::vector<unsigned char> garbler_public_value_data = network_driver->read();
  DHPublicValue_Message garbler_public_value_s;
  garbler_public_value_s.deserialize(garbler_public_value_data);

  // Send g^a
  DHPublicValue_Message evaluator_public_value_s;
  evaluator_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> evaluator_public_value_data;
  evaluator_public_value_s.serialize(evaluator_public_value_data);
  network_driver->send(evaluator_public_value_data);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      garbler_public_value_s.public_value);
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
 * 1) Receive the garbled circuit and the garbler's input
 * 2) Reconstruct the garbled circuit and input the garbler's inputs
 * 3) Retrieve evaluator's inputs using OT
 * 4) Evaluate gates in order (use `evaluate_gate` to help!)
 * 5) Send final labels to the garbler
 * 6) Receive final output
 * `input` is the evaluator's input for each gate
 * You may find `resize` useful before running OT
 * You may also find `string_to_byteblock` useful for converting OT output to wires 
 * Disconnect and throw errors only for invalid MACs
 */
std::string EvaluatorClient::run(std::vector<int> input)
{
  // Key exchange
  auto keys = this->HandleKeyExchange();

  // Receive the garbled circuit
  auto garbler_to_eval_circuit_msg_data = this->network_driver->read();
  GarblerToEvaluator_GarbledTables_Message garbled_circuit_msg;
  ReceiverToSender_OTPublicValue_Message receiver_to_sender_OT_pub_msg;
  auto [decrypted_garbler_to_eval_circuit_msg_data, garbler_to_eval_circuit_msg_decrypted] = this->crypto_driver->decrypt_and_verify(keys.first, keys.second, garbler_to_eval_circuit_msg_data);
  if (!garbler_to_eval_circuit_msg_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the garbler to evaluator circuit message");
  }
  garbled_circuit_msg.deserialize(decrypted_garbler_to_eval_circuit_msg_data);

  // Receive the garbled inputs
  auto garbler_to_eval_garbler_inputs_data = this->network_driver->read();
  GarblerToEvaluator_GarblerInputs_Message garbler_to_eval_garbler_inputs_msg;
  auto [decrypted_garbler_to_eval_garbler_inputs_msg_data, garbler_to_eval_garbler_inputs_msg_decrypted] = this->crypto_driver->decrypt_and_verify(keys.first, keys.second, garbler_to_eval_garbler_inputs_data);
  if (!garbler_to_eval_garbler_inputs_msg_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the garbler to evaluator inputs message");
  }
  garbler_to_eval_garbler_inputs_msg.deserialize(decrypted_garbler_to_eval_garbler_inputs_msg_data);

  // Reconstruct the garbled circuit and input the garbler's inputs
  std::vector<GarbledWire> list_of_wires;
  list_of_wires.resize(this->circuit.num_wire);
  std::vector<GarbledGate> garbled_gates = garbled_circuit_msg.garbled_tables;

  // Populate list of wires with garbler's inputs
  for (int i = 0; i < this->circuit.garbler_input_length; i++)
  {
    list_of_wires[i] = garbler_to_eval_garbler_inputs_msg.garbler_inputs[i];
  }

  // Retrieve evaluator's input using OT and populate list of wires with evaluator's input
  for (int i = 0; i < this->circuit.evaluator_input_length; i++)
  {
    GarbledWire garbled_wire;
    auto evaluator_input = string_to_byteblock(this->ot_driver->OT_recv(input[i]));
    garbled_wire.value = evaluator_input;
    list_of_wires[i + this->circuit.garbler_input_length] = garbled_wire;
  }

  // Evaluate gates in order. Iterate through all gates and just evaluate them. We get the LHS and RHS from the original circuit.
  for (int i = 0; i < garbled_gates.size(); i++)
  {
    GarbledWire output_wire;
    auto current_gate = garbled_circuit_msg.garbled_tables[i];
    auto lhs_wire = list_of_wires[this->circuit.gates[i].lhs];
    auto rhs_wire = list_of_wires[this->circuit.gates[i].rhs];
    if (this->circuit.gates[i].type == GateType::AND_GATE || this->circuit.gates[i].type == GateType::XOR_GATE)
    {
      output_wire = evaluate_gate(current_gate, lhs_wire, rhs_wire);
    }
    else
    {
      GarbledWire dummy_wire;
      dummy_wire.value = DUMMY_RHS;
      output_wire = evaluate_gate(current_gate, lhs_wire, dummy_wire);
    }
    list_of_wires[this->circuit.gates[i].output] = output_wire;
  }

  // Send final labels to the garbler
  EvaluatorToGarbler_FinalLabels_Message eval_to_garbler_final_labels_msg;
  eval_to_garbler_final_labels_msg.final_labels = list_of_wires;
  auto eval_to_garbler_final_labels_msg_bytes = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &eval_to_garbler_final_labels_msg);
  this->network_driver->send(eval_to_garbler_final_labels_msg_bytes);

  // Receive final output
  auto garbler_to_eval_final_output_msg_data = this->network_driver->read();
  GarblerToEvaluator_FinalOutput_Message garbler_to_eval_final_output_msg;
  auto [decrypted_garbler_to_eval_garbler_final_output_msg_data, garbler_to_eval_garbler_final_output_msg_decrypted] = this->crypto_driver->decrypt_and_verify(keys.first, keys.second, garbler_to_eval_final_output_msg_data);
  if (!garbler_to_eval_garbler_final_output_msg_decrypted)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not decrypt the garbler to evaluator final output message");
  }
  garbler_to_eval_final_output_msg.deserialize(decrypted_garbler_to_eval_garbler_final_output_msg_data);
  return garbler_to_eval_final_output_msg.final_output;
}

/**
 * Evaluate gate.
 * You may find CryptoPP::xorbuf and CryptoDriver::hash_inputs useful.
 * To determine if a decryption is valid, use verify_decryption.
 * To retrieve the label from a decryption, use snip_decryption.
 */
GarbledWire EvaluatorClient::evaluate_gate(GarbledGate gate, GarbledWire lhs,
                                           GarbledWire rhs)
{
  GarbledWire wire_output;
  // First, calculate SHA(LHS, RHS)
  auto original_hashed_inputs = this->crypto_driver->hash_inputs(lhs.value, rhs.value);
  // XOR the hashed inputs with each of the gate's entries (which represent the outputs)
  for (int i = 0; i < gate.entries.size(); i++)
  {
    CryptoPP::SecByteBlock hashed_inputs = original_hashed_inputs;
    xorbuf(hashed_inputs, gate.entries[i], original_hashed_inputs.size());
    if (verify_decryption(hashed_inputs))
    {
      wire_output.value = snip_decryption(hashed_inputs);
    }
  }
  return wire_output;
}

/**
 * Verify decryption. A valid dec should end with LABEL_TAG_LENGTH bits of 0s.
 */
bool EvaluatorClient::verify_decryption(CryptoPP::SecByteBlock decryption)
{
  CryptoPP::SecByteBlock trail(decryption.data() + LABEL_LENGTH,
                               LABEL_TAG_LENGTH);
  return byteblock_to_integer(trail) == CryptoPP::Integer::Zero();
}

/**
 * Returns the first LABEL_LENGTH bits of a decryption.
 */
CryptoPP::SecByteBlock
EvaluatorClient::snip_decryption(CryptoPP::SecByteBlock decryption)
{
  CryptoPP::SecByteBlock head(decryption.data(), LABEL_LENGTH);
  return head;
}

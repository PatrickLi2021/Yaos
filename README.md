# Yao's

This project implements a simple version of Yao's Garbled Circuits with a corresponding implementation of Oblivious Transfer (OT). These cryptographic primitives are foundational in the realm of secure multi-party computation (SMPC), enabling two parties to collaboratively compute a function over their inputs while keeping the inputs private.

## Oblivious Transfer
**Oblivious transfer**__ is a cryptographic protocol essential for secure multi-party computation. It allows a receiver to select one of two messages from a sender without revealing their choice to the sender, and the receiver learns nothing about the unselected message. Here are the steps for how it works:

1. **Message Preparation:** The sender prepares 2 messages, _m<sub>0</sub>_ and _m<sub>1</sub>_.
2. **Key Exchange:** The sender generates a Diffie-Hellman (DH) key pair - _(a, g<sup>a</sup>)_ - and shares _g<sup>a</sup>_ with the receiver. The receiver then generates their DH key pair _(b, g<sup>b</sup>)_ and selects the key exchange response. If they wish to receive _m<sub>0</sub>_, they send _g<sup>b</sup>_. If they wish to receive _m<sub>1</sub>_, they send _g<sup>b</sup> * g<sup>a</sup>_.
3. **Shared Keys:** Both parties compute shared keys using HKDF (a key derivation function). The sender computes _k<sub>0</sub>_ and _k<sub>1</sub>_ for both messages and the receiver computes _k<sub>s</sub> _(based on their choice bit _c_).
4. **Message Encryption:** The sender encrypts _m<sub>0</sub>_ and _m<sub>1</sub>_ with _k<sub>0</sub>_ and _k<sub>1</sub>_, respectively, and sends both ciphertexts to the receiver.
5. **Decryption:** The receiver decrypts their chosen ciphertext using _k<sub>s</sub>_.

The simplicity of this protocol, built on Diffie-Hellman key exchange, provides robust security while ensuring privacy.

## Yao's Garbled Circuits
Yao’s Garbled Circuits enable secure two-party computation (2PC) by obfuscating a Boolean circuit so that two parties can jointly compute a function without revealing their inputs. The process involves several key concepts. A circuit is represented using the Bristol Format, which consists of AND, XOR, and NOT gates. Each wire in the circuit is assigned two labels (random 128-bit strings) representing 0 and 1. For AND and XOR gates, four ciphertexts are generated, corresponding to all input combinations, while NOT gates require two ciphertexts. Double encryption ensures security.

The evaluation process involves the evaluator processing the garbled circuit gate-by-gate, starting with input labels obtained via OT. Output labels are decrypted to reveal the final result. This protocol ensures privacy and correctness while allowing any Boolean function to be securely computed.

## Project Structure
The project is organized as follows:
- `src/cmd/garbler.cxx`: Entry point for the Garbler binary, invoking the Garbler class
- `src/cmd/evaluator.cxx`: Entry point for the Evaluator binary, invoking the Evaluator class
- `src/drivers/ot_driver.cxx`: Contains the implementation for OT functionality
- `src/pkg/garbler.cxx`: Implements garbled circuit generation
- `src/pkg/evaluator.cxx`: Implements garbled circuit evaluation

## Implementation Details

### Implementing Oblivious Transfer
The OT implementation involves the following functions:

- `OTDriver::OT_send`: Handles the sender’s operations, including key pair generation, encryption, and message transmission
- `OTDriver::OT_recv`: Handles the receiver’s operations, including key pair generation, choice bit handling, and decryption

### Garbled Circuit Generation

The Garbler generates the garbled circuit with:
- `GarblerClient::generate_labels`: Assigns random labels to circuit wires
- `GarblerClient::generate_gates`: Creates garbled gates with double encryption using input labels
- `GarblerClient::encrypt_label`: Encrypts labels for output wires based on gate logic

### Garbled Circuit Evaluation
The Evaluator computes the circuit using:
- `EvaluatorClient::evaluate_gate`: Processes gates sequentially, decrypting output labels based on input labels
- `EvaluatorClient::run`: Manages the overall evaluation, integrating input labels obtained via OT and producing output labels

## Usage
1. Compile the project using `make`.
2. Run the garbler and evaluator binaries using `./garbler <circuit-file> <input>` and `./evaluator <circuit-file> <input>` respectively.
3. Input files should be in Bristol Format, and inputs should match the circuit's requirements.

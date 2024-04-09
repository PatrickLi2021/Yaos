#pragma once

#include <fstream>
#include <stdio.h>
#include <string>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/integer.h>
#include <crypto++/secblock.h>

// ================================================
// REGULAR CIRCUIT
// ================================================

namespace GateType
{
  enum T
  {
    AND_GATE = 1,
    XOR_GATE = 2,
    NOT_GATE = 3
  };
};

struct Gate
{
  GateType::T type;
  int lhs;    // index corresponding to lhs wire
  int rhs;    // index corresponding to rhs wire
  int output; // index corresponding to output wire
};

struct Circuit
{
  int num_gate, num_wire, garbler_input_length, evaluator_input_length,
      output_length;
  std::vector<Gate> gates;
};
Circuit parse_circuit(std::string filename);

// ================================================
// GARBLED CIRCUIT
// ================================================

// Each wire can either be associated with an input value (LHS, RHS) or an output value
struct GarbledWire
{
  CryptoPP::SecByteBlock value;
};

// Each GarbledGate has a list of entries that correspond to each of the 4 (or 2) ciphertexts
struct GarbledGate
{
  std::vector<CryptoPP::SecByteBlock> entries;
};

struct GarbledLabels
{
  std::vector<GarbledWire> zeros;
  std::vector<GarbledWire> ones;
};

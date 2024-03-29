import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import { circomkitInstance, getSignal, poseidon } from "./utils";

describe("Commitment", () => {
  let circuit: WitnessTester;

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("Commitment", {
      file: "Commitment",
      template: "Commitment",
    });
  });

  test("should return commitment from amount, public key and nonce", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt(),
        fc.bigInt(),
        fc.bigInt(),
        async (amount: bigint, publicKey: bigint, nonce: bigint) => {
          const circuitInputs = { amount, publicKey, nonce };

          const witness = await circuit.calculateWitness(circuitInputs);
          await circuit.expectConstraintPass(witness);
          const output = await getSignal(circuit, witness, "out");
          const hash = poseidon(circuitInputs);

          return output === hash;
        },
      ),
    );
  });
});

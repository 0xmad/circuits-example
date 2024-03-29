import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import { circomkitInstance, getSignal, poseidon } from "./utils";

describe("Nullifier", () => {
  let circuit: WitnessTester;

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("Nullifier", {
      file: "Nullifier",
      template: "Nullifier",
    });
  });

  test("should return nullifier from commitment, merkle path and signature", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt(),
        fc.bigInt(),
        async (commitment: bigint, signature: bigint) => {
          const circuitInputs = { commitment, signature };

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

import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import { circomkitInstance, getSignal, poseidon } from "./utils";

describe("Signature", () => {
  let circuit: WitnessTester;

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("Signature", {
      file: "Signature",
      template: "Signature",
    });
  });

  test("should return signature from private key, commitment and merkle path", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt(),
        fc.bigInt(),
        async (privateKey: bigint, commitment: bigint) => {
          const circuitInputs = { privateKey, commitment };

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

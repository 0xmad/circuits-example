import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import { circomkitInstance, getSignal, poseidon } from "./utils";

describe("Keypair", () => {
  let circuit: WitnessTester;

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("Keypair", { file: "Keypair", template: "Keypair" });
  });

  test("should generate keypair properly", async () => {
    await fc.assert(
      fc.asyncProperty(fc.bigInt(), async (privateKey: bigint) => {
        const circuitInputs = { privateKey };

        const witness = await circuit.calculateWitness(circuitInputs);
        await circuit.expectConstraintPass(witness);
        const publicKey = await getSignal(circuit, witness, "publicKey");
        const hash = poseidon(circuitInputs);

        return publicKey === hash;
      }),
    );
  });
});

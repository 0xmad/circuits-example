import { IMT } from "@zk-kit/imt";
import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import { TREE_ARITY, TREE_DEPTH, TREE_ZERO, circomkitInstance, getSignal, poseidon2 } from "./utils";

describe("MerkleProof", () => {
  let circuit: WitnessTester;

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("MerkleProof", {
      file: "MerkleProof",
      template: "MerkleProof",
      params: [5],
    });
  });

  test("should generate merkle proof properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt(),
        fc.array(fc.bigInt(), { minLength: 1 }),
        async (leaf: bigint, pathElements: bigint[]) => {
          const tree = new IMT(poseidon2, TREE_DEPTH, TREE_ZERO, TREE_ARITY, [...pathElements, leaf]);
          const { pathIndices, siblings } = tree.createProof(tree.leaves.length - 1);
          const circuitInputs = { leaf, pathElements: siblings, pathIndices };

          const witness = await circuit.calculateWitness(circuitInputs);
          await circuit.expectConstraintPass(witness);
          const root = await getSignal(circuit, witness, "root");

          return root === tree.root;
        },
      ),
    );
  });
});

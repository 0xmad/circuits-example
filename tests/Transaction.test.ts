import { type WitnessTester } from "circomkit";
import fc from "fast-check";

import {
  TREE_ARITY,
  TREE_DEPTH,
  TREE_ZERO,
  circomkitInstance,
  generateKeypair,
  getSignal,
  poseidon,
  poseidon2,
} from "./utils";
import { IMT } from "@zk-kit/imt";

describe("Transaction", () => {
  let circuit: WitnessTester;
  let defaultCircuitParams: Record<string, number | number[] | number[][] | bigint | bigint[] | bigint[][]>;

  const LEVELS = 5;
  const NUM_INPUTS = 2;
  const NUM_OUTPUTS = 2;

  const defaultTree = new IMT(poseidon2, TREE_DEPTH, TREE_ZERO, TREE_ARITY);
  const defaultKeypair = generateKeypair();
  const defaultPrivateKeys = [defaultKeypair[0], defaultKeypair[0]];
  const defaultPublicKeys = defaultPrivateKeys.map((privateKey) => poseidon({ privateKey }));
  const defaultNonces = [0n, 1n];
  const defaultInputAmounts = [4n, 5n];
  const defaultOutputAmounts = [1n, 8n];

  const defaultCommitments = defaultInputAmounts.map((amount, index) =>
    poseidon({ amount, publicKey: defaultPublicKeys[index], nonce: defaultNonces[index] }),
  );
  const defaultSignatures = defaultPrivateKeys.map((privateKey, index) =>
    poseidon({ privateKey, commitment: defaultCommitments[index] }),
  );
  const defaultInputNullifiers = defaultCommitments.map((commitment, index) =>
    poseidon({ commitment, signature: defaultSignatures[index] }),
  );

  beforeAll(async () => {
    circuit = await circomkitInstance.WitnessTester("Transaction", {
      file: "Transaction",
      template: "Transaction",
      params: [LEVELS, NUM_INPUTS, NUM_OUTPUTS],
    });
  });

  beforeEach(() => {
    defaultCommitments.forEach((commitment) => {
      defaultTree.insert(commitment);
    });

    const proof1 = defaultTree.createProof(defaultTree.leaves.length - 2);
    const proof2 = defaultTree.createProof(defaultTree.leaves.length - 1);

    defaultCircuitParams = {
      publicAmount: 0n,
      extraDataHash: 1234321n,
      root: defaultTree.root,
      inputAmounts: defaultInputAmounts,
      outputAmounts: defaultOutputAmounts,
      inputNullifiers: defaultInputNullifiers,
      privateKeys: defaultPrivateKeys,
      publicKeys: defaultPublicKeys,
      inputNonces: defaultNonces,
      outputNonces: defaultNonces,
      pathElements: [proof1.siblings as bigint[], proof2.siblings as bigint[]],
      pathIndices: [proof1.pathIndices, proof2.pathIndices],
    };
  });

  afterEach(() => {
    defaultTree.leaves.forEach((_, index) => {
      defaultTree.delete(index);
    });
  });

  test("should prove transaction properly", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigInt({ min: 0n, max: 20n }),
        fc.bigInt({ min: 0n, max: 10n ** 38n }),
        fc.array(fc.bigInt(), { minLength: NUM_INPUTS, maxLength: NUM_INPUTS }),
        fc.array(fc.bigInt({ min: 0n, max: 20n }), { minLength: NUM_INPUTS, maxLength: NUM_INPUTS }),
        fc.array(fc.bigInt({ min: 0n, max: 20n }), { minLength: NUM_OUTPUTS, maxLength: NUM_OUTPUTS }),
        async (
          publicAmount: bigint,
          extraDataHash: bigint,
          privateKeys: bigint[],
          inputAmounts: bigint[],
          outputAmounts: bigint[],
        ) => {
          const totalInputSum = inputAmounts.reduce((acc, x) => acc + x, 0n);
          const totalOutputSum = outputAmounts.reduce((acc, x) => acc + x, 0n);
          fc.pre(publicAmount + totalInputSum === totalOutputSum);

          const tree = new IMT(poseidon2, TREE_DEPTH, TREE_ZERO, TREE_ARITY);

          const nonces = privateKeys.map((_, index) => BigInt(index));
          const publicKeys = privateKeys.map((privateKey) => poseidon({ privateKey }));
          const commitments = inputAmounts.map((amount, index) =>
            poseidon({ amount, publicKey: publicKeys[index], nonce: nonces[index] }),
          );
          const signatures = privateKeys.map((privateKey, index) =>
            poseidon({ privateKey, commitment: commitments[index] }),
          );
          const inputNullifiers = commitments.map((commitment, index) =>
            poseidon({ commitment, signature: signatures[index] }),
          );
          commitments.forEach((commitment) => tree.insert(commitment));

          const proof1 = tree.createProof(tree.leaves.length - 2);
          const proof2 = tree.createProof(tree.leaves.length - 1);

          const circuitInputs = {
            publicAmount,
            extraDataHash,
            root: tree.root,
            inputAmounts,
            outputAmounts,
            inputNullifiers,
            privateKeys,
            publicKeys,
            inputNonces: nonces,
            outputNonces: nonces,
            pathElements: [proof1.siblings, proof2.siblings],
            pathIndices: [proof1.pathIndices, proof2.pathIndices],
          };

          const witness = await circuit.calculateWitness(circuitInputs);
          await circuit.expectConstraintPass(witness);
          const extraDataSquare = await getSignal(circuit, witness, "extraDataSquare");

          return extraDataSquare === extraDataHash ** 2n;
        },
      ),
    );
  });

  test("should throw an error if nonces don't match", async () => {
    const commitments = defaultInputAmounts.map((amount, index) =>
      poseidon({ amount, publicKey: defaultPublicKeys[index], nonce: 9000n }),
    );
    const signatures = defaultPrivateKeys.map((privateKey, index) =>
      poseidon({ privateKey, commitment: commitments[index] }),
    );
    const inputNullifiers = commitments.map((commitment, index) =>
      poseidon({ commitment, signature: signatures[index] }),
    );
    commitments.forEach((commitment) => {
      defaultTree.insert(commitment);
    });

    await circuit.expectFail({ ...defaultCircuitParams, root: defaultTree.root, inputNullifiers });
  });

  test("should throw an error if private keys don't match", async () => {
    const keypair = generateKeypair();

    await circuit.expectFail({ ...defaultCircuitParams, privateKeys: [keypair[0], keypair[0]] });
  });

  test("should throw an error if amounts don't match", async () => {
    await circuit.expectFail({ ...defaultCircuitParams, publicAmount: 9000n });
    await circuit.expectFail({ ...defaultCircuitParams, inputAmounts: [9000n, 0n], outputAmounts: [1n, 2n] });
  });

  test("should throw an error if merkle trees don't match", async () => {
    defaultTree.insert(9000n);

    const proof1 = defaultTree.createProof(defaultTree.leaves.length - 2);
    const proof2 = defaultTree.createProof(defaultTree.leaves.length - 1);

    await circuit.expectFail({
      ...defaultCircuitParams,
      pathElements: [proof1.siblings as bigint[], proof2.siblings as bigint[]],
      pathIndices: [proof1.pathIndices, proof2.pathIndices],
    });
  });

  test("should throw an error for amount overflow", async () => {
    await circuit.expectFail({
      ...defaultCircuitParams,
      inputAmounts: [2n ** 256n, 2n ** 256n],
    });

    await circuit.expectFail({
      ...defaultCircuitParams,
      outputAmounts: [2n ** 256n, 2n ** 256n],
    });
  });

  test("should throw an error if nullifier is duplicated", async () => {
    await circuit.expectFail({
      ...defaultCircuitParams,
      root: defaultTree.root,
      inputNullifiers: [defaultInputNullifiers[0], defaultInputNullifiers[0]],
    });
  });
});

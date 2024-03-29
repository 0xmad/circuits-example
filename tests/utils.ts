import { derivePublicKey } from "@zk-kit/eddsa-poseidon";
import { poseidonPerm } from "@zk-kit/poseidon-cipher";
import { Circomkit, type WitnessTester, type CircomkitConfig } from "circomkit";
import { randomBytes } from "crypto";

import fs from "fs";
import path from "path";

const configFilePath = path.resolve(__dirname, "..", "circomkit.json");
const config = JSON.parse(fs.readFileSync(configFilePath, "utf-8")) as CircomkitConfig;

export const circomkitInstance = new Circomkit({
  ...config,
  verbose: false,
});

export const TREE_DEPTH = 5;
export const TREE_ZERO = 0;
export const TREE_ARITY = 2;

export const getSignal = async (tester: WitnessTester, witness: bigint[], name: string): Promise<bigint> => {
  const signalFullName = `main.${name}`;
  const out = await tester.readWitness(witness, [signalFullName]);

  return BigInt(out[signalFullName]);
};

export const generatePrivateKey = (): bigint => BigInt(`0x${randomBytes(32).toString("hex")}`);

export const generatePublicKey = (privKey: bigint): [bigint, bigint] => {
  const key = derivePublicKey(privKey.toString());

  return [BigInt(key[0]), BigInt(key[1])];
};

export const generateKeypair = (): [bigint, [bigint, bigint]] => {
  const privateKey = generatePrivateKey();
  const publicKey = generatePublicKey(privateKey);

  return [privateKey, publicKey];
};

export const poseidon = (inputs: Record<string, bigint>): bigint =>
  poseidonPerm([0n, ...Object.values(inputs).map((input) => BigInt(input))])[0];

export const poseidon2 = (inputs: bigint[]): bigint => poseidonPerm([0n, ...inputs.map((input) => BigInt(input))])[0];

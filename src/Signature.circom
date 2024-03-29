pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Signature() {
    /**
     * Private key input
     */
    signal input privateKey;

    /**
     * Commitment input
     */
    signal input commitment;

    /**
     * Signature output
     */
    signal output out;

    /**
     * Poseidon hasher
     */
    component hasher = Poseidon(2);

    hasher.inputs[0] <== privateKey;
    hasher.inputs[1] <== commitment;

    out <== hasher.out;
}
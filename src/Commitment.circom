pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Commitment() {
    /**
     * Amount
     */
    signal input amount;

    /**
     * Public key
     */
    signal input publicKey;

    /**
     * Random nonce
     */
    signal input nonce;

    /**
     * Commitment output
     */
    signal output out;

    /**
     * Poseidon hasher
     */
    component hasher = Poseidon(3);

    hasher.inputs[0] <== amount;
    hasher.inputs[1] <== publicKey;
    hasher.inputs[2] <== nonce;

    out <== hasher.out;
}

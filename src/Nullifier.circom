pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Nullifier() {
    /**
     * Commitment - PoseidonHash(amount, publicKey, nonce)
     */
    signal input commitment;

    /**
     * Signature - PoseidonHash(privateKey, commitment, merklePath)
     */
    signal input signature;

    /**
     * Nullifier output
     */
    signal output out;

    /**
     * Poseidon hasher
     */
    component hasher = Poseidon(2);
    
    hasher.inputs[0] <== commitment;
    hasher.inputs[1] <== signature;

    out <== hasher.out;
}

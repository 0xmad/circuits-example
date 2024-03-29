pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Keypair() {
    /**
     * Private key input
     */
    signal input privateKey;

    /**
     * Public key output
     */
    signal output publicKey;

    /**
     * Poseidon hasher
     */
    component hasher = Poseidon(1);

    hasher.inputs[0] <== privateKey;
    publicKey <== hasher.out;
}
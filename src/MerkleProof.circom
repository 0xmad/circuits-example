pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

/**
 * Verifies that merkle proof is correct for given merkle root and leaf
 */
template MerkleProof(levels) {
    /**
     * Merkle tree leaf input
     */
    signal input leaf;

    /**
     * Merkle tree elements
     */
    signal input pathElements[levels];

    /**
     * Array of bits (0|1) selectors.
     * Telling whether given path element is on the left or right side of merkle tree
     */
    signal input pathIndices[levels];

    /**
     * Merkle tree root
     */
    signal output root;

    /**
     * Switcher component
     */
    component switcher[levels];

    /**
     * Poseidon hasher
     */
    component hasher[levels];

    for (var level = 0; level < levels; level++) {
        pathIndices[level] * (1 - pathIndices[level]) === 0;

        switcher[level] = Switcher();
        switcher[level].L <== level == 0 ? leaf : hasher[level - 1].out;
        switcher[level].R <== pathElements[level];
        switcher[level].sel <== pathIndices[level];

        hasher[level] = Poseidon(2);
        hasher[level].inputs[0] <== switcher[level].outL;
        hasher[level].inputs[1] <== switcher[level].outR; 
    }

    root <== hasher[levels - 1].out;
}


pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

include "./Commitment.circom";
include "./MerkleProof.circom";
include "./Keypair.circom";
include "./Nullifier.circom";
include "./Signature.circom";

template Transaction(levels, numInputs, numOutputs) {
    /**
     * Amount overflow must fit into 248 bits to prevent overflow
     */
    var OVERFLOW_THRESHOLD = 248;

    /**
     * Merkle root containing all the nullifiers
     */
    signal input root;
    
    /**
     * Sum of publicly known money flowing in, which has to equal to: totalOutputSum - totalInputSum
     */
    signal input publicAmount;

    /**
     * Extra data hash that are not used in the circuit, but need to be binded to the proof to prevent
     * someone from modifying them after the proof generation (e.g relayer address).
     */
    signal input extraDataHash;

    /**
     * Public nullifiers for each input
     */
    signal input inputNullifiers[numInputs];

    /**
     * Private input amounts for each input
     */
    signal input inputAmounts[numInputs];

    /**
     * Private output amounts for each output
     */
    signal input outputAmounts[numOutputs];

    /**
     * Private keys for each input
     */
    signal input privateKeys[numInputs];

    /**
     * Public keys for each output
     */
    signal input publicKeys[numOutputs];

    /**
     * Private nonce values for each input 
     */
    signal input inputNonces[numInputs];

    /**
     * Private nonce values for each output 
     */
    signal input outputNonces[numOutputs];

    /**
     * Private Merkle path indices for each input
     */
    signal input pathIndices[numInputs][levels];

    /**
     * Private Merkle path elements for each input
     */
    signal input pathElements[numInputs][levels];

    /**
     * Keypair
     */
    component keypairs[numInputs];

    /**
     * Signature
     */
    component signatures[numInputs];

    /**
     * Poseidon input commitment hasher
     */
    component inputCommitmentHasher[numInputs];

    /**
     * Poseidon output commitment hasher
     */
    component outputCommitmentHasher[numOutputs];

    /**
     * Poseidon nullifier hasher
     */
    component nullifiers[numInputs];

    /**
     * Merkle tree
     */
    component merkleProofs[numInputs];

    /**
     * Check Merkle proof if amount is not zero
     */
    component checkRoots[numInputs];

    /**
     * Check input amount for overflow
     */
    component inputAmountCheck[numOutputs];

    /**
     * Check output amount for overflow
     */
    component outputAmountCheck[numOutputs];

    /**
     * Check same nullifiers
     */
    component sameNullifiers[numInputs * (numInputs - 1) / 2];

    var totalInputSum = 0;
    var totalOutputSum = 0;

    for (var tx = 0; tx < numInputs; tx++) {
        keypairs[tx] = Keypair();
        keypairs[tx].privateKey <== privateKeys[tx];

        inputAmountCheck[tx] = Num2Bits(OVERFLOW_THRESHOLD);
        inputAmountCheck[tx].in <== inputAmounts[tx];

        inputCommitmentHasher[tx] = Commitment();
        inputCommitmentHasher[tx].amount <== inputAmounts[tx];
        inputCommitmentHasher[tx].publicKey <== keypairs[tx].publicKey;
        inputCommitmentHasher[tx].nonce <== inputNonces[tx];

        signatures[tx] = Signature();
        signatures[tx].privateKey <== privateKeys[tx];
        signatures[tx].commitment <== inputCommitmentHasher[tx].out;

        nullifiers[tx] = Nullifier();
        nullifiers[tx].commitment <== inputCommitmentHasher[tx].out;
        nullifiers[tx].signature <== signatures[tx].out;
        nullifiers[tx].out === inputNullifiers[tx];

        merkleProofs[tx] = MerkleProof(levels);
        merkleProofs[tx].leaf <== inputCommitmentHasher[tx].out;

        for (var level = 0; level < levels; level++) {
            merkleProofs[tx].pathElements[level] <== pathElements[tx][level];
            merkleProofs[tx].pathIndices[level] <== pathIndices[tx][level];
        }

        checkRoots[tx] = ForceEqualIfEnabled();
        checkRoots[tx].in[0] <== root;
        checkRoots[tx].in[1] <== merkleProofs[tx].root;
        checkRoots[tx].enabled <== inputAmounts[tx];

        totalInputSum += inputAmounts[tx];   
    }

    for (var tx = 0; tx < numOutputs; tx++) {
        outputCommitmentHasher[tx] = Commitment();
        outputCommitmentHasher[tx].amount <== outputAmounts[tx];
        outputCommitmentHasher[tx].publicKey <== publicKeys[tx];
        outputCommitmentHasher[tx].nonce <== outputNonces[tx];

        outputAmountCheck[tx] = Num2Bits(OVERFLOW_THRESHOLD);
        outputAmountCheck[tx].in <== outputAmounts[tx];

        totalOutputSum += outputAmounts[tx];
    }

    var index = 0;

    for (var i = 0; i < numInputs - 1; i++) {
        for (var j = i + 1; j < numInputs; j++) {
            sameNullifiers[index] = IsEqual();
            sameNullifiers[index].in[0] <== inputNullifiers[i];
            sameNullifiers[index].in[1] <== inputNullifiers[j];
            sameNullifiers[index].out === 0;
            index++;
        }
    }

    totalInputSum + publicAmount === totalOutputSum;

    signal extraDataSquare <== extraDataHash * extraDataHash;
}



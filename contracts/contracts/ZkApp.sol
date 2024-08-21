//SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.8.0;

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[3] memory input
    ) external view returns (bool r);
}

contract ZkApp {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    address public immutable verifier;
    uint256[3][] public records; // Records of public signals

    constructor(address verifier_) {
        verifier = verifier_;
    }

    /**
     * @dev Public Signals will be recorded on chain
     */
    function record(uint256[3] memory publicSignals, Proof memory proof)
        public
    {
        require(verify(publicSignals, proof), "SNARK verification failed");
        records.push(publicSignals);
    }

    /**
     * @dev Verifies the public signals and proof
     */
    function verify(uint256[3] memory publicSignals, Proof memory proof)
        public
        view
        returns (bool)
    {
        bool result = IVerifier(verifier).verifyProof(
            proof.a,
            proof.b,
            proof.c,
            publicSignals
        );
        return result;
    }

    function totalRecords() public view returns (uint256) {
        return records.length;
    }
}

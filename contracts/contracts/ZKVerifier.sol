// SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
/**
 * @title IVerifier
 * @dev Interface for a smart contract that verifies a zero-knowledge proof using a set of inputs and outputs.
 */
interface IVerifier {
    /**
     * @dev Verifies a zero-knowledge proof using a set of inputs and outputs.
     * @param a An array of two uint256 values that represent the first part of the proof.
     * @param b A 2D array of two uint256 values that represents the second part of the proof.
     * @param c An array of two uint256 values that represents the third part of the proof.
     * @param input An array of three uint256 values that represent the public inputs of the proof.
     * @return r boolean indicating whether the proof is valid or not.
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[3] memory input
    ) external view returns (bool r);
}

/**
 * @title ZKVerifier
 * @dev A contract that allows recording and verification of zk-SNARK proofs with public signals.
 * @author Credore
 * @notice Use this contract to record and verify zk-SNARK proofs with public signals.
 */
contract ZKVerifier is AccessControl {
    /**
     * @dev Struct containing the proof data.
     * @param a The first part of the proof.
     * @param b The second part of the proof.
     * @param c The third part of the proof.
     */
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    bytes32 public constant RECORDER_ROLE = keccak256("RECORD_ROLE"); // Role required to record a proof
    address public immutable verifier; // Address of the IVerifier contract
    mapping(bytes32 => uint256[3]) public records; // Records of public signals
    mapping(bytes32 => Proof) private proofs;
    uint256 public numRecords; // Total number of records

    event RecordAdded(bytes32 id); // Event emitted when a new proof is recorded

    /**
     * @dev Initializes the contract with the specified verifier address and sets the DEFAULT_ADMIN_ROLE and RECORDER_ROLE roles to the deployer.
     * @param verifier_ The address of the IVerifier contract that will be used to verify proofs.
     * Requirements:
     * - The verifier_ parameter must be a valid contract address.
     */
    constructor(address verifier_) {
        verifier = verifier_;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(RECORDER_ROLE, msg.sender);
    }

    /**
     * @dev Records a new proof with the specified ID, public signals, and proof data.
     * @param _id The ID of the record being added.
     * @param publicSignals An array of three uint256 values that represent the public inputs of the proof.
     * @param proof The proof data that is being recorded.
     * Requirements:
     * - The caller must have the RECORDER_ROLE.
     * - The publicSignals parameter must be a valid array of three uint256 values.
     * - The proof parameter must be a valid zk-SNARK proof.
     * - The record with the specified ID must not already exist in the records mapping.
     */
    function record(bytes32 _id, uint256[3] memory publicSignals, Proof memory proof)
        public
        onlyRole(RECORDER_ROLE)
        validPublicSignals(publicSignals)
        validProof(proof)
        recordDoesNotExist(_id)
    {
        require(verify(publicSignals, proof), "SNARK signature verification failed");
        // Add record to the mapping
        records[_id] = publicSignals;
        proofs[_id] = proof;
        numRecords++;

        // Emit an event with the record ID
        emit RecordAdded(_id);
    }

    /**
     * @dev Verifies the public signals anda proof by calling the IVerifier contract's verifyProof function.
     * @param publicSignals The public signals that correspond to the proof.
     * @param proof The proof that is being verified.
     * @return A boolean indicating whether the proof is valid or not.
     * Requirements:
     * - The public signals must be valid.
     * - The proof must be valid.
     */
    function verify(uint256[3] memory publicSignals, Proof memory proof)
        public
        view
        validPublicSignals(publicSignals)
        validProof(proof)
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

    /**
     * @dev Verifies the asset by calling the IVerifier contract's verifyProof function.
     * @param _id id of the asset
     */
    function verifyById(string memory _id)
        public
        view
        returns (bool)
    {
        bytes32 id = stringToBytes32(_id);
        bool result = IVerifier(verifier).verifyProof(
            proofs[id].a,
            proofs[id].b,
            proofs[id].c,
            records[id]
        );
        return result;
    }

    function totalRecords() public view returns (uint256) {
        return numRecords;
    }

    function getProof(bytes32 id) public view returns (Proof memory) {
        return proofs[id];
    }

    function stringToBytes32(string memory text) public pure returns (bytes32) {
        bytes32 result;
        assembly {
            result := mload(add(text, 32))
        }
        return result;
    }
    
    /**
     * @dev Grants RECORDER_ROLE to the specified account.
     * @param account The address of the account to grant the role to.
     * Requirements:
     * - The caller must have the DEFAULT_ADMIN_ROLE.
     */
    function grantRecorderRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(RECORDER_ROLE, account);
    }

    /**
     * @dev Revokes the RECORDER_ROLE role from the specified account.
     * @param account The account to revoke the RECORDER_ROLE role from.
     * Requirements:
     * - The caller must have the DEFAULT_ADMIN_ROLE role.
     */
    function revokeRecorderRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(RECORDER_ROLE, account);
    }

    /**
     * @dev The validPublicSignals modifier is used to validate that the provided public signals array is valid before executing the function. It checks if each value in the array is greater than 0.
     * @param publicSignals An array of three unsigned integers representing the public signals to be validated.
     * Requirements:
     * - The three values in the publicSignals array must be greater than 0.
     */
    modifier validPublicSignals(uint256[3] memory publicSignals) {
        require(publicSignals[0] > 0, "Invalid public signal");
        require(publicSignals[1] > 0, "Invalid public signal");
        require(publicSignals[2] > 0, "Invalid public signal");
        _;
    }

    /**
     * @dev Modifier to check the validity of a given proof.
     * @param proof The proof to check.
     * Requirements:
     * - proof must have valid values for all fields of the struct Proof, namely a, b, and c.
     */
    modifier validProof(Proof memory proof) {
        require(proof.a[0] > 0, "Invalid proof");
        require(proof.a[1] > 0, "Invalid proof");
        require(proof.b[0][0] > 0, "Invalid proof");
        require(proof.b[0][1] > 0, "Invalid proof");
        require(proof.b[1][0] > 0, "Invalid proof");
        require(proof.b[1][1] > 0, "Invalid proof");
        require(proof.c[0] > 0, "Invalid proof");
        require(proof.c[1] > 0, "Invalid proof");
        _;
    }

    /**
     * @dev This modifier checks whether a record with the given id already exists in the records mapping. If the record already exists, it will revert with an error message "Record already exists". Otherwise, it will execute the function.
     * @param id The id of the record to check.
     */
    modifier recordDoesNotExist(bytes32 id) {
        require(records[id][0] == 0, "Record already exists");
        _;
    }
}
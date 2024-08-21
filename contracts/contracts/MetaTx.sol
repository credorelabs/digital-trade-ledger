// SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";

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

interface IDigitalAssetRegistry {
    struct Asset {
        bytes32 id;
        uint256 nftId;
        bytes32 merkleRoot;
        bytes32 assetType;
        bytes32 lei;
        uint256 leiVerificationDate;
        bytes32 originator;
        bytes32 status;
        uint104 scalarFieldValueCount;
    }
    function getAsset(bytes32 id) external view returns (Asset memory);
}

contract MetaTx is AccessControl, ReentrancyGuard {
    using Address for address;
    using ECDSA for bytes32;
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
    
    address private verifier; // Address of the IVerifier contract
    address private digitalAssetRegistry;

    /**
     * @dev Initializes the contract and sets the DEFAULT_ADMIN_ROLE role to the deployer.
     */
    constructor() {                
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function setVerifier(address verifier_) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(verifier_ != address(0), "Invalid address");
        require(Address.isContract(verifier_), "Address must be a contract");
        verifier = verifier_;
    }

    function setDigitalAssetRegistry(address digitalAssetRegistry_) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(digitalAssetRegistry_ != address(0), "Invalid address");
        require(Address.isContract(digitalAssetRegistry_), "Address must be a contract");
        digitalAssetRegistry = digitalAssetRegistry_;
    }

    /**
     * @dev Execute an operation on a target contract using the provided data.
      * The method also ensures the validity of public signals and zero knowledge proof.
      *
      * @param target The address of the target contract to execute the operation on.
      * @param data The bytes data containing the encoded method and parameters for the target contract.
      * @param publicSignals An array of 3 uint256 values representing the public signals used in the SNARK verification process.
      * @param proof The Proof struct containing the proof data required for SNARK signature verification.
      *
      * @return response The bytes data returned by the target contract as a result of successful execution.
      *
      * Requirements:
      * - The caller must have the DEFAULT_ADMIN_ROLE.
      * - The target address must not be a zero address.
      * - The data length must be greater than 0.
      * - The publicSignals and proof must pass the SNARK signature verification.
      * - The execution of the operation on the target contract must be successful.
      */
    function execute(address target, bytes memory data, uint256[3] memory publicSignals, Proof memory proof) 
        public 
        onlyRole(DEFAULT_ADMIN_ROLE)
        nonReentrant
        validPublicSignals(publicSignals)
        validProof(proof)
        returns (bytes memory) 
    {
        require(target != address(0), "Invalid target address");
        require(data.length > 0, "Invalid data length");
        require(verify(publicSignals, proof), "SNARK signature verification failed");
        (bool success, bytes memory response) = target.call(data);
        require(success, "Execution failed");
        return response;
    }

    /**
     * @dev Execute a transfer of NFT tokens between two addresses using the provided data.
      * The method also ensures the validity of the provided addresses, NFT ID, amount, and signature.
      *
      * @param _target The address of the target contract to execute the NFT transfer on.
      * @param _from The address from which the NFT tokens will be transferred.
      * @param _to The address to which the NFT tokens will be transferred.
      * @param _nftId The ID of the NFT token being transferred.
      * @param _amount The amount of NFT tokens to be transferred.
      * @param _data Bytes data associated with the transfer.
      * @param _operator The address of the operator responsible for the transfer.
      * @param _signature The signature data used for verification of the transfer.
      * @param _methodData The bytes data containing the encoded method and parameters for the target contract.
      *
      * Requirements:
      * - The caller must have the DEFAULT_ADMIN_ROLE.
      * - The target, from, to, and operator addresses must not be zero addresses.
      * - The NFT ID must be a valid token ID (non-negative).
      * - The amount of NFT tokens to be transferred must be greater than 0.
      * - The signature length must be exactly 65 bytes.
      * - The provided signature must pass the verification process.
      * - The execution of the NFT transfer on the target contract must be successful.
      */
    function executeTransferNFT(
        address _target,
        address _from,
        address _to,
        uint256 _nftId,
        uint256 _amount,
        bytes memory _data,
        address _operator,
        bytes calldata _signature,
        bytes memory _methodData
    ) 
        public 
        onlyRole(DEFAULT_ADMIN_ROLE)
        nonReentrant
    {
        require(_target != address(0), "Invalid target address");
        require(_from != address(0), "Invalid from address");
        require(_to != address(0), "Invalid to address");
        require(_nftId >= 0, "Invalid token ID");
        require(_amount > 0, "Invalid token amount");
        require(_operator != address(0), "Invalid operator address");
        require(_signature.length == 65, "Invalid signature length");
        require(verifyTransferNFT(_from, _to, _nftId, _amount, _data, _operator, _signature), "Signature verification failed");
        (bool success, bytes memory response) = _target.call(_methodData);
        assembly {
            // Consume the unused variable to suppress the warning
            let unused := response
        }
        require(success, "Execution failed");
    }

    /**
     * @dev Execute the issuance of an NFT token to a specified owner using the provided data.
      * The method also ensures the validity of the provided addresses, NFT ID, signature, and method data.
      *
      * @param _target The address of the target contract to execute the NFT issuance on.
      * @param _id The unique ID of the NFT token being issued.
      * @param _status The status of the tokenized status
      * @param _owner The address of the owner who will receive the NFT token.
      * @param _data Bytes data associated with the NFT issuance.
      * @param _operator The address of the operator responsible for the NFT issuance.
      * @param _signature The signature data used for verification of the NFT issuance.
      * @param _methodData The bytes data containing the encoded method and parameters for the target contract.
      *
      * Requirements:
      * - The caller must have the DEFAULT_ADMIN_ROLE.
      * - The target, owner, and operator addresses must not be zero addresses.
      * - The NFT ID must not be an empty bytes32 value.
      * - The status must not be an empty bytes32 value.
      * - The signature length must be greater than 0.
      * - The method data length must be greater than 0.
      * - The provided signature must pass the verification process.
      * - The execution of the NFT issuance on the target contract must be successful.
      */
    function executeIssueNFT(
        address _target,
        bytes32 _id, 
        bytes32 _status,
        address _owner,
        bytes memory _data,
        address _operator,
        bytes calldata _signature,
        bytes memory _methodData
    ) 
        public 
        onlyRole(DEFAULT_ADMIN_ROLE)
        nonReentrant
        returns (bytes memory) 
    {
        require(_target != address(0), "Invalid target address");
        require(_id != bytes32(0), "Invalid token ID");
        require(_owner != address(0), "Invalid owner address");
        require(_status != bytes32(0), "Invalid status");
        require(_operator != address(0), "Invalid operator address");
        require(_signature.length > 0, "Invalid signature length");
        require(_methodData.length > 0, "Invalid method data length");
        require(verifyIssueNFT(_id, _owner, _status, _data, _operator, _signature), "Signature verification failed");
        (bool success, bytes memory response) = _target.call(_methodData);
        
        require(success, "Execution failed");
        return response;
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
     * @dev Verifies a transfer of an NFT by checking the message signature against the sender's address.
     * @param _from The address of the NFT owner initiating the transfer.
     * @param _to The address to which the NFT will be transferred.
     * @param _id The unique identifier of the NFT to be transferred.
     * @param _amount The amount of NFTs to be transferred (used for ERC1155 tokens).
     * @param _data Additional data to be sent with the transfer, if any.
     * @param _operator The address of the authorized operator performing the transfer on behalf of the owner.
     * @param signature The signature of the message hash, signed by the owner (_from).
     * @return A boolean value indicating whether the provided signature is valid and matches the owner's address.
     * @notice  This function is private and should only be called internally within the contract.
     *          It takes all necessary parameters for a transfer of an NFT, calculates the message hash
     *          and Ethereum-signed message hash, and verifies the signature against the expected owner's
     *          address. This is particularly useful in the context of meta transactions, where users can
     *          delegate the transfer of their NFTs to other parties (relayers) without giving up control
     *          of their assets.
     * @custom:warning This function assumes that the input parameters are well-formed and valid.
     *                 Ensure to validate user inputs and handle edge cases before calling this function.
     */
    function verifyTransferNFT(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _operator,
        bytes memory signature
    ) private pure returns (bool) {
        bytes32 messageHash = getTransferNFTHash(_from, _to, _id, _amount, _data, _operator);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _from;
    }

    function verifyIssueNFT(
        bytes32 _id, 
        address _owner,
        bytes32 _status,
        bytes memory _data,
        address _operator,
        bytes memory signature
    ) private pure returns (bool) {
        bytes32 messageHash = getIssueNFTHash(_id, _owner, _status, _data, _operator);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _owner;
    }

    function getIssueNFTHash(
        bytes32 _id, 
        address _owner,
        bytes32 _status,
        bytes memory _data,
        address _operator
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_id, _owner, _status, _data, _operator));
    }

    function getTransferNFTHash(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _operator
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_from, _to, _id, _amount, _data, _operator));
    }

    function getAsset(bytes32 _id) public view returns (IDigitalAssetRegistry.Asset memory){
        return IDigitalAssetRegistry(digitalAssetRegistry).getAsset(_id);
    }

    function getEthSignedMessageHash(
        bytes32 _messageHash
    ) private pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
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
}

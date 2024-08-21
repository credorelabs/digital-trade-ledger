//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "./interfaces/IDigitalAssetRegistry.sol";

/**
 * @title DigitalAssetRegistry
 * @dev This contract implements a registry for digital assets that can be represented by ERC1155 tokens.
 * @dev It allows administrators with the DEFAULT_ADMIN_ROLE and the TOKEN_ISSUER_ROLE to add and update digital assets, and issue ERC1155 tokens to represent these assets.
 * @dev It also allows for NFTs to be transferred on behalf of an owner by the TOKEN_ISSUER_ROLE.
 * @dev The contract can be paused by the DEFAULT_ADMIN_ROLE.
 * @dev The contract also implements the IDigitalAssetRegistry interface.
 * @dev The contract uses AccessControl and ERC1155 contracts from the OpenZeppelin library.
 */
contract DigitalAssetRegistry is IDigitalAssetRegistry, AccessControl, ERC1155 {
    using Counters for Counters.Counter;

    bytes32 public constant TOKEN_ISSUER_ROLE = keccak256("TOKEN_ISSUER_ROLE");
    Counters.Counter private _tokenIds;
    bool private paused;
    address private metaTxContract;
    //address private operator;    

    mapping(bytes32 => Asset) private assets;

    event AssetAdded(bytes32 id);
    event AssetUpdated(bytes32 id);
    event NFTTransferred(uint256 nftId, address from, address to);
    event NFTIssued(uint256 nftId, address to);

    modifier whenNotPaused() {
        require(!paused, "The contract is currently paused");
        _;
    }

    modifier onlyMetaTxContract() {
        require(msg.sender == metaTxContract, "Only Meta Transaction contract is allowed to call this method");
        _;
    }

    constructor(string memory uri) ERC1155(uri) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(TOKEN_ISSUER_ROLE, msg.sender);
        paused = false;        
    }    

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        paused = true;
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        paused = false;
    }

    function setMetaTxContractAddress(address _metaTxContract) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        metaTxContract = _metaTxContract;
    }

    /**
     * @notice Adds a new digital asset to the registry
     * @dev Only an administrator with DEFAULT_ADMIN_ROLE can call this method.
     * @dev The contract must not be paused when calling this method.
     * @param _id The unique identifier for the new asset
     * @param _merkleRoot The merkle root hash of the asset data
     * @param _assetType The type of asset
     * @param _lei The legal entity identifier associated with the asset
     * @param _leiVerificationDate The date the LEI was verified
     * @param _originator The originator of the asset
     * @param _status The current status of the asset
     * @param _status Scalar Field Value Count
     * @param _scalarFieldValueCount Scalar Field Value Count
     */
    function addAsset(
        bytes32 _id, 
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 _scalarFieldValueCount
        ) 
        external 
        override 
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenNotPaused
    {
        require(_id != bytes32(0), "Invalid Id");
        require(!assetExists(_id), "Asset already exists");
        require(_merkleRoot != bytes32(0), "Invalid MerkleRoot");
        require(_assetType != bytes32(0), "Invalid Asset Type");
        require(_lei != bytes32(0), "Invalid LEI");
        require(_leiVerificationDate > 0, "Invalid LEI Verification Date");
        require(_originator != bytes32(0), "Invalid Originator");
        require(_status != bytes32(0), "Invalid Status");  

        assets[_id] = Asset({
            id: _id,
            nftId: 0,
            merkleRoot: _merkleRoot,
            assetType: _assetType,
            lei: _lei,
            leiVerificationDate: _leiVerificationDate,
            originator: _originator,
            status: _status,
            scalarFieldValueCount: _scalarFieldValueCount
        });

        emit AssetAdded(_id);
    }

    /**
     * @dev Adds a new digital asset to the registry using a meta-transaction.
     * @param _id The unique identifier of the asset to be added.
     * @param _merkleRoot The Merkle root hash of the asset's content.
     * @param _assetType The type of the asset.
     * @param _lei The Legal Entity Identifier of the asset.
     * @param _leiVerificationDate The date on which the LEI was verified.
     * @param _originator The originator of the asset.
     * @param _status The status of the asset.
     * @param _scalarFieldValueCount Scalar Field Value Count.
     * Requirements:
     * - Only the Meta-Transaction contract is allowed to call this function.
     * - The contract must not be paused.
     * - The asset ID must not be zero.
     * - The asset must not already exist in the registry.
     * - The Merkle root hash, asset type, LEI, LEI verification date, originator, and status must not be zero.
     * Effects:
     * - Adds the asset to the registry by creating a new Asset struct and adding it to the assets mapping.
     * - Emits an AssetAdded event.
     */
    function addAssetUsingMetaTx(
        bytes32 _id, 
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 _scalarFieldValueCount
        ) 
        external
        override
        whenNotPaused
        onlyMetaTxContract
    {
        require(_id != bytes32(0), "Invalid Id");
        require(!assetExists(_id), "Asset already exists");
        require(_merkleRoot != bytes32(0), "Invalid MerkleRoot");
        require(_assetType != bytes32(0), "Invalid Asset Type");
        require(_lei != bytes32(0), "Invalid LEI");
        require(_leiVerificationDate > 0, "Invalid LEI Verification Date");
        require(_originator != bytes32(0), "Invalid Originator");
        require(_status != bytes32(0), "Invalid Status");
        
        assets[_id] = Asset({
            id: _id,
            nftId: 0,
            merkleRoot: _merkleRoot,
            assetType: _assetType,
            lei: _lei,
            leiVerificationDate: _leiVerificationDate,
            originator: _originator,
            status: _status,
            scalarFieldValueCount: _scalarFieldValueCount
        });

        emit AssetAdded(_id);
    }

    function issueNFTUsingMetaTx(
        bytes32 _id, 
        address _owner,
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 _scalarFieldValueCount
        ) 
        external
        override
        whenNotPaused
        onlyMetaTxContract
        returns (uint256)
    {
        require(_id != bytes32(0), "Invalid Id");
        require(!assetExists(_id), "Asset already exists");
        require(_merkleRoot != bytes32(0), "Invalid MerkleRoot");
        require(_assetType != bytes32(0), "Invalid Asset Type");
        require(_lei != bytes32(0), "Invalid LEI");
        require(_leiVerificationDate > 0, "Invalid LEI Verification Date");
        require(_originator != bytes32(0), "Invalid Originator");
        require(_status != bytes32(0), "Invalid Status");
        
        assets[_id] = Asset({
            id: _id,
            nftId: 0,
            merkleRoot: _merkleRoot,
            assetType: _assetType,
            lei: _lei,
            leiVerificationDate: _leiVerificationDate,
            originator: _originator,
            status: _status,
            scalarFieldValueCount: _scalarFieldValueCount
        });

        emit AssetAdded(_id);

        uint256 nftId = _tokenIds.current();     
        _mint(_owner, nftId, 1, "0x");
        _tokenIds.increment();
        assets[_id].nftId = nftId;
        assets[_id].status = _status;
        emit NFTIssued(nftId, _owner);
        return nftId;
    }

    /**
     * @notice Updates a new digital asset to the registry
     * @dev Only an administrator with DEFAULT_ADMIN_ROLE can call this method.
     * @dev The contract must not be paused when calling this method.
     * @param _id The unique identifier for the asset
     * @param _merkleRoot The merkle root hash of the asset data
     * @param _assetType The type of asset
     * @param _lei The legal entity identifier associated with the asset
     * @param _leiVerificationDate The date the LEI was verified
     * @param _originator The originator of the asset
     * @param _status The current status of the asset
     * @param _scalarFieldValueCount Scalar Field Value Count.
     */
    function updateAsset(
        bytes32 _id, 
        uint256 _nftId,
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 _scalarFieldValueCount
        ) 
        external 
        override 
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenNotPaused
    {        
        require(_id != bytes32(0), "Invalid Id");
        require(assetExists(_id), "Asset does not exist");
        require(_merkleRoot != bytes32(0), "Invalid MerkleRoot");
        require(_assetType != bytes32(0), "Invalid Asset Type");
        require(_lei != bytes32(0), "Invalid LEI");
        require(_leiVerificationDate > 0, "Invalid LEI Verification Date");
        require(_originator != bytes32(0), "Invalid Originator");
        require(_status != bytes32(0), "Invalid Status");
        
        assets[_id].merkleRoot = _merkleRoot;
        assets[_id].nftId = _nftId;
        assets[_id].assetType = _assetType;
        assets[_id].lei = _lei;
        assets[_id].leiVerificationDate = _leiVerificationDate;
        assets[_id].originator = _originator;
        assets[_id].status = _status;
        assets[_id].scalarFieldValueCount = _scalarFieldValueCount;

        emit AssetUpdated(_id);
    }

    /**
     * @dev Updates a new digital asset to the registry using a meta-transaction.
     * @param _id The unique identifier of the asset to be updated.
     * @param _merkleRoot The Merkle root hash of the asset's content.
     * @param _assetType The type of the asset.
     * @param _lei The Legal Entity Identifier of the asset.
     * @param _leiVerificationDate The date on which the LEI was verified.
     * @param _originator The originator of the asset.
     * @param _status The status of the asset.
     * @param _scalarFieldValueCount Scalar Field Value Count.
     * Requirements:
     * - Only the Meta-Transaction contract is allowed to call this function.
     * - The contract must not be paused.
     * - The asset ID must not be zero.
     * - The asset must already exist in the registry.
     * - The Merkle root hash, asset type, LEI, LEI verification date, originator, and status must not be zero.
     * Effects:
     * - Updatesthe asset to the registr.
     * - Emits an AssetUpdated event.
     */
    function updateAssetUsingMetaTx(
        bytes32 _id, 
        uint256 _nftId,
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 _scalarFieldValueCount
        )         
        external
        override
        whenNotPaused
        onlyMetaTxContract
    {        
        require(_id != bytes32(0), "Invalid Id");
        require(assetExists(_id), "Asset does not exist");
        require(_merkleRoot != bytes32(0), "Invalid MerkleRoot");
        require(_assetType != bytes32(0), "Invalid Asset Type");
        require(_lei != bytes32(0), "Invalid LEI");
        require(_leiVerificationDate > 0, "Invalid LEI Verification Date");
        require(_originator != bytes32(0), "Invalid Originator");
        require(_status != bytes32(0), "Invalid Status");
        
        assets[_id].merkleRoot = _merkleRoot;
        assets[_id].nftId = _nftId;
        assets[_id].assetType = _assetType;
        assets[_id].lei = _lei;
        assets[_id].leiVerificationDate = _leiVerificationDate;
        assets[_id].originator = _originator;
        assets[_id].status = _status;
        assets[_id].scalarFieldValueCount = _scalarFieldValueCount;
        emit AssetUpdated(_id);
    }

    function issueNFT(
        bytes32 _id,
        address _owner,
        bytes32 _status
    ) external override onlyMetaTxContract whenNotPaused returns (uint256) {
        require(assetExists(_id), "Asset does not exist");
        uint256 nftId = _tokenIds.current();     
        _mint(_owner, nftId, 1, "0x");
        _tokenIds.increment();
        assets[_id].nftId = nftId;
        assets[_id].status = _status;
        emit NFTIssued(nftId, _owner);
        return nftId;
    }

    function transferToken(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _operator
    ) external override onlyMetaTxContract whenNotPaused {        
        _setApprovalForAll(_from, _operator, true);

        // Perform the token transfer
        _safeTransferFrom(_from, _to, _id, _amount, _data);
        emit NFTTransferred(_id, _from, _to);
    }    

    function getIssueNFTHash(
        bytes32 _id, 
        address _owner,
        uint _nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_id, _owner, _nonce));
    }

    function getTransferNFTHash(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _contractAddress
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_from, _to, _id, _amount, _data, _contractAddress));
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

    function setURI(string memory newuri) public onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        _setURI(newuri);
    }

    function ownerBalance(address owner, uint256 _tokenId) public view whenNotPaused returns (uint256) {
        return balanceOf(owner, _tokenId);
    }

    function assetExists(bytes32 id) public view whenNotPaused returns (bool) {
        return (assets[id].id == id);
    }

    function getAsset(bytes32 id) external override view returns (Asset memory) {
        return assets[id];
    }

    function verifyTransferNFT(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _contractAddress,
        bytes memory signature
    ) private pure returns (bool) {
        bytes32 messageHash = getTransferNFTHash(_from, _to, _id, _amount, _data, _contractAddress);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _from;
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
}

//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

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

    function addAsset(bytes32 id, bytes32 merkleRoot, bytes32 assetType, bytes32 lei, uint256 leiVerificationDate, bytes32 originator, bytes32 status, uint104 scalarFieldValueCount) external;    
    function getAsset(bytes32 id) external view returns (Asset memory);
    function updateAsset(bytes32 id, uint256 nftId, bytes32 merkleRoot, bytes32 assetType, bytes32 lei, uint256 leiVerificationDate, bytes32 originator, bytes32 status, uint104 scalarFieldValueCount) external;    
    function setMetaTxContractAddress(address _metaTxContract) external;
    function addAssetUsingMetaTx(bytes32 id, bytes32 merkleRoot, bytes32 assetType, bytes32 lei, uint256 leiVerificationDate, bytes32 originator, bytes32 status, uint104 scalarFieldValueCount) external;
    function updateAssetUsingMetaTx(bytes32 id, uint256 nftId, bytes32 merkleRoot, bytes32 assetType, bytes32 lei, uint256 leiVerificationDate, bytes32 originator, bytes32 status, uint104 scalarFieldValueCount) external;    
    function issueNFT(
        bytes32 _id, 
        address _owner,
        bytes32 _status
    ) external returns (uint256);
    function transferToken(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount,
        bytes memory _data,
        address _operator
    ) external;
    function issueNFTUsingMetaTx(
        bytes32 _id, 
        address _owner,
        bytes32 _merkleRoot,
        bytes32 _assetType, 
        bytes32 _lei, 
        uint256 _leiVerificationDate, 
        bytes32 _originator,
        bytes32 _status,
        uint104 scalarFieldValueCount
        ) 
        external returns (uint256);
}
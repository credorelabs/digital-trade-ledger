// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.6.7 <0.9.0;
 

contract DLPC {

mapping (string => uint) public dlpcMerkleRoots;

constructor (string memory _dlpcId, uint256 _merkleRoot) public {
        dlpcMerkleRoots[_dlpcId] = _merkleRoot;
    }

function setDLPCMerkleRoot(string memory _dlpcId, uint256 _merkleRoot) public {
        dlpcMerkleRoots[_dlpcId] = _merkleRoot;
    }

function getDLPCMerkleRoot(string memory _dlpcId) public view returns (uint) {
        return dlpcMerkleRoots[_dlpcId];
    }

}
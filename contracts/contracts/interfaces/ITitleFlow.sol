// SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;

interface ITitleFlow {
    // Gasless ITitleEscrowV2 methods
    function nominate(
        address _nominee,
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function transferBeneficiary(
        address _nominee,
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function transferHolder(
        address _newHolder,
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function transferOwners(
        address _nominee,
        address _newHolder,
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function rejectTransferBeneficiary(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function rejectTransferHolder(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function rejectTransferOwners(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function returnToIssuer(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    function shred(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;

    // View functions
    function beneficiary(address _titleEscrow) external view returns (address);
    function holder(address _titleEscrow) external view returns (address);
    function prevBeneficiary(address _titleEscrow) external view returns (address);
    function prevHolder(address _titleEscrow) external view returns (address);
    function active(address _titleEscrow) external view returns (bool);
    function nominee(address _titleEscrow) external view returns (address);
    function registry(address _titleEscrow) external view returns (address);
    function tokenId(address _titleEscrow) external view returns (uint256);
    function isHoldingToken(address _titleEscrow) external returns (bool);
    function nonce(address _titleEscrow, address _user) external view returns (uint256);

    // Initialization and admin
    function initialize(address _attorney, address _owner) external;
    function setAttorney(address newAttorney) external;
}

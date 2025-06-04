// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "../interfaces/ITitleEscrowV2.sol";
contract TitleEscrowMock is ITitleEscrowV2 {
    address public override beneficiary;
    address public override holder;
    address public override prevBeneficiary;
    address public override prevHolder;
    address public override nominee;
    bool public override active;
    address public override registry;
    uint256 public override tokenId;

    bool public shouldFail; // Toggle to simulate failures
    bool public shredSuccess = true;

    constructor() {
        beneficiary = address(0x1234); // Dummy initial values
        holder = address(0x5678);
        prevBeneficiary = address(0);
        prevHolder = address(0);
        nominee = address(0);
        active = true;
        registry = address(0xABCD);
        tokenId = 42;
        shouldFail = false;
    }

    // Toggle failure mode for testing
    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function nominate(address _nominee, bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        nominee = _nominee;
    }

    function transferBeneficiary(address _nominee, bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        prevBeneficiary = beneficiary;
        beneficiary = _nominee;
    }

    function transferHolder(address _newHolder, bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        prevHolder = holder;
        holder = _newHolder;
    }

    function transferOwners(address _nominee, address _newHolder, bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        prevBeneficiary = beneficiary;
        beneficiary = _nominee;
        prevHolder = holder;
        holder = _newHolder;
    }

    function rejectTransferBeneficiary(bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        nominee = address(0);
    }

    function rejectTransferHolder(bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        prevHolder = address(0);
    }

    function rejectTransferOwners(bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        nominee = address(0);
        prevHolder = address(0);
    }

    function returnToIssuer(bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        active = false;
    }

    function shred(bytes calldata _remark) external override {
        if (shouldFail) revert("Mock failure");
        active = false;
    }

    function setShredSuccess(bool _success) external {
        shredSuccess = _success;
    }

    function isHoldingToken() external override returns (bool) {
        return active;
    }

    // Setter for testing state changes
    function setState(
        address _beneficiary,
        address _holder,
        address _prevBeneficiary,
        address _prevHolder,
        address _nominee,
        bool _active,
        address _registry,
        uint256 _tokenId
    ) external {
        beneficiary = _beneficiary;
        holder = _holder;
        prevBeneficiary = _prevBeneficiary;
        prevHolder = _prevHolder;
        nominee = _nominee;
        active = _active;
        registry = _registry;
        tokenId = _tokenId;
    }

    // IERC721Receiver implementation (required by ITitleEscrowV2)
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
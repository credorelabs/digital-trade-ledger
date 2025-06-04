// SPDX-License-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

interface INominateContract {
    function nominate(
        address _nominee,
        bytes calldata _remark,
        address _titleEscrow,
        bytes calldata _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;
}

interface ITitleFlow {
    function transferOwners(
        address _nominee,
        address _newHolder,
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

    function shred(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external;
}

interface ITitleEscrowV2 {
    function beneficiary() external view returns (address);
    function registry() external view returns (address);
    function tokenId() external view returns (uint256);
    function transferBeneficiary(address nominee, bytes calldata remark) external returns (bool);
}

contract MaliciousTitleEscrow is ITitleEscrowV2 {
    address public target;
    address public attacker;
    address public beneficiary;
    address public holder;
    address public nominee;
    address public pendingBeneficiary;
    address public pendingHolder;
    bool public active;
    address public registry;
    uint256 public tokenId;
    bytes public lastData;
    bytes public lastSignature;
    uint256 public lastNonce;

    constructor(address _target) {
        target = _target;
        beneficiary = msg.sender; // Initialize beneficiary to deployer
        registry = address(this); // Mock registry
        tokenId = 42; // Mock token ID
        active = true;
    }

    function setState(
        address _beneficiary,
        address _holder,
        address _nominee,
        address _pendingBeneficiary,
        address _pendingHolder,
        bool _active,
        address _registry,
        uint256 _tokenId
    ) external {
        beneficiary = _beneficiary;
        holder = _holder;
        nominee = _nominee;
        pendingBeneficiary = _pendingBeneficiary;
        pendingHolder = _pendingHolder;
        active = _active;
        registry = _registry;
        tokenId = _tokenId;
    }

    function attack(
        address _nominee,
        bytes calldata _remark,
        bytes calldata _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external {
        attacker = msg.sender;
        // Now call target.nominate, passing this contract as the _titleEscrow
        INominateContract(target).nominate(_nominee, _remark, address(this), _data, _signature, _nonce);
    }

    // This function gets called via .call(...) from nominate()
    function nominate(bytes calldata, bytes calldata) external returns (bool) {
        // Try to reenter during .call()
        bytes memory emptyRemark = "";
        bytes memory emptyData = "";
        bytes memory dummySig = hex"00";
        try INominateContract(target).nominate(attacker, emptyRemark, address(this), emptyData, dummySig, 999) {
            return true;
        } catch {
            return false;
        }
    }

    // External function to initiate transferBeneficiary attack
    function attackTransferBeneficiary(
        address _nominee,
        bytes calldata _remark,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external {
        attacker = msg.sender;
        // Store parameters for reentrancy
        lastData = _data;
        lastSignature = _signature;
        lastNonce = _nonce;
        // Call target.transferBeneficiary, passing this contract as _titleEscrow
        ITitleFlow(target).transferBeneficiary(_nominee, _remark, address(this), _data, _signature, _nonce);
    }

    // ITitleEscrowV2: Called by target.transferBeneficiary
    function transferBeneficiary(address _nominee, bytes calldata _remark) external override returns (bool) {
        // Attempt reentrancy with stored parameters
        try ITitleFlow(target).transferBeneficiary(
            _nominee,
            _remark,
            address(this),
            lastData,
            lastSignature,
            lastNonce
        ) {
            // If reentrancy succeeds (it shouldn't), continue
        } catch {
            // Expected: Reentrancy fails due to nonReentrant
        }

        // Do not update beneficiary to ensure state remains unchanged
        // beneficiary = _nominee;
        return true;
    }

    function attackShred(
        bytes calldata _remark,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) external {
        attacker = msg.sender;
        ITitleFlow(target).shred(_remark, address(this), _data, _signature, _nonce);
    }

    function shred(bytes calldata _remark) external returns (bool) {
        // Attempt reentrancy with new valid parameters
        bytes memory reentrantData = abi.encode(
            target,           // titleFlow.address
            address(this),    // MaliciousTitleEscrow
            address(0),       // zeroAddress
            address(0),       // zeroAddress
            0,                // nonce
            8                 // ActionType.Shred
        );
        // Note: In a real attack, the signature would need to be valid.
        // For testing, we rely on the reentrancy guard to revert before signature validation.
        bytes memory dummySignature = new bytes(65); // Invalid signature
        ITitleFlow(target).shred(_remark, address(this), reentrantData, dummySignature, 0);

        active = false;
        return true;
    }

    function transferOwners(address _nominee, address _newHolder, bytes calldata _remark) external returns (bool) {
        // Attempt reentrancy
        bytes memory reentrantData = abi.encode(
            target,           // titleFlow.address
            address(this),    // MaliciousTitleEscrow
            _nominee,         // Same nominee
            _newHolder,       // Same newHolder
            0,                // nonce
            9                 // ActionType.OwnersTransfer
        );
        bytes memory dummySignature = new bytes(65); // Invalid signature
        ITitleFlow(target).transferOwners(_nominee, _newHolder, _remark, address(this), reentrantData, dummySignature, 0);

        beneficiary = _nominee;
        holder = _newHolder;
        return true;
    }

    // IERC721Receiver implementation
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
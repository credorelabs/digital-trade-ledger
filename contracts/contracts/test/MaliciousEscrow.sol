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
    function transferBeneficiary(
        address _nominee,
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
    address public override beneficiary;
    address public override registry;
    uint256 public override tokenId;
    bytes public lastData;
    bytes public lastSignature;
    uint256 public lastNonce;

    constructor(address _target) {
        target = _target;
        beneficiary = msg.sender; // Initialize beneficiary to deployer
        registry = address(this); // Mock registry
        tokenId = 42; // Mock token ID
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
}
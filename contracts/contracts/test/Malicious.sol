//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;

interface ITitleFlowFactory {
    function testReentrancy(address target) external;
}

contract Malicious {
    ITitleFlowFactory public factory;
    bool public attackActive;

    constructor(address _factory) {
        factory = ITitleFlowFactory(_factory);
    }

    function tryReenter() external {
        if (!attackActive) {
            attackActive = true;
            factory.testReentrancy(address(this));
        }
    }

    function startAttack() external {
        factory.testReentrancy(address(this));
    }
}
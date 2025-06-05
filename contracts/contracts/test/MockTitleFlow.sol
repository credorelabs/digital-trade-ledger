//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;

contract MockTitleFlow {
    function initialize(address _admin, address _owner) external {
        revert("Mock initialize failure");
    }

    // Mock owner getter
    function owner() external view returns (address) {
        return address(0);
    }

    // Mock hasRole
    function hasRole(bytes32, address) external pure returns (bool) {
        return false;
    }
}
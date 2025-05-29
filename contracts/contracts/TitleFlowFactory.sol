//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/ITitleFlowFactory.sol";
import "./interfaces/TitleEscrowErrorsV2.sol";
import "./TitleFlow.sol";

contract TitleFlowFactory is AccessControl, TitleEscrowErrorsV2, ITitleFlowFactory, ReentrancyGuard{
    address public override implementation;
    bytes32 public constant ATTORNEY_ADMIN_ROLE = keccak256("ATTORNEY_ADMIN_ROLE");
    constructor() {        
        implementation = address(new TitleFlow());
        _setupRole(ATTORNEY_ADMIN_ROLE, msg.sender);
    }

    function create(address _owner) external override onlyRole(ATTORNEY_ADMIN_ROLE) returns (address) {
        if ( _owner == address(0) ){
                revert InvalidAddress();
        }

        bytes32 salt = keccak256(abi.encodePacked(msg.sender, _owner));
        address titleFlow = Clones.cloneDeterministic(implementation, salt);
        TitleFlow(titleFlow).initialize(msg.sender, _owner);

        emit TitleFlowCreated(msg.sender, _owner);
        return titleFlow;
    }

    function getAddress(address _owner) external override view returns (address) {
        if ( _owner == address(0) ){
                revert InvalidAddress();
        }
        return Clones.predictDeterministicAddress(implementation, keccak256(abi.encodePacked(msg.sender, _owner)));
    }

    function setupAdmin(address _newAdmin) public onlyRole(ATTORNEY_ADMIN_ROLE){
        _setupRole(ATTORNEY_ADMIN_ROLE, _newAdmin);
    }

    // Test function for reentrancy
    uint256 public testValue;
    function testReentrancy(address target) external nonReentrant {
        testValue = 1;
        (bool success, ) = target.call(abi.encodeWithSignature("tryReenter()"));
        require(success, "Call failed");
        testValue = 2;
    }
}
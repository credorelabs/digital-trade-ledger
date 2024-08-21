//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/ETDWalletFactoryErrors.sol";
import "./interfaces/IETDWalletFactory.sol";
import "./ETDWallet.sol";

contract ETDWalletFactory is AccessControl, IETDWalletFactory, ETDWalletFactoryErrors, ReentrancyGuard{
    address public override implementation;
    bytes32 public constant ATTORNEY_ADMIN_ROLE = keccak256("ATTORNEY_ADMIN_ROLE");
    constructor() {        
        implementation = address(new ETDWallet());
        _setupRole(ATTORNEY_ADMIN_ROLE, msg.sender);
    }

    function create(address _owner) external override onlyRole(ATTORNEY_ADMIN_ROLE) returns (address) {
        if ( _owner == address(0) ){
                revert InvalidAddress();
        }

        bytes32 salt = keccak256(abi.encodePacked(msg.sender, _owner));
        address etdWallet = Clones.cloneDeterministic(implementation, salt);
        ETDWallet(etdWallet).initialize(msg.sender, _owner);

        emit ETDWalletCreated(msg.sender, _owner);
        return etdWallet;
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
}
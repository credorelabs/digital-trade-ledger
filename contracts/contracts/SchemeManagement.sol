//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/ISchemeManagement.sol";


contract SchemeManagement is ISchemeManagement, AccessControl {
    struct Scheme {
        bytes32 id;
        bytes32 name;
        bytes32 description;
        bytes32 merkleRoot;
    }

    bytes32 public constant SCHEME_ADMIN_ROLE = keccak256("SCHEME_ADMIN_ROLE");

    mapping(bytes32 => Scheme) public schemes;

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function addScheme(bytes32 schemeId, bytes32 schemeName, bytes32 description, bytes32 merkleRoot) external override {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Must have DEFAULT_ADMIN_ROLE to add scheme");
        require(!schemeExists(schemeId), "Scheme ID already exists");
        
        schemes[schemeId] = Scheme({
            id: schemeId,
            name: schemeName,
            description: description,
            merkleRoot: merkleRoot
        });
    }


    function updateScheme(bytes32 schemeId, bytes32 name, bytes32 description, bytes32 merkleRoot) external override{
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Must have DEFAULT_ADMIN_ROLE to update schemes");
        require(schemeExists(schemeId), "Scheme ID does not exist");

        schemes[schemeId].name = name;
        schemes[schemeId].description = description;
        schemes[schemeId].merkleRoot = merkleRoot;
    }

    function removeScheme(bytes32 schemeId) external override {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Must have DEFAULT_ADMIN_ROLE to remove scheme");
        require(schemeExists(schemeId), "Scheme ID does not exist");

        delete schemes[schemeId];
    }

    function grantSchemeAdminRole(address account, bytes32 schemeId) external override {
        require(schemeExists(schemeId), "Scheme ID does not exist");
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Must have DEFAULT_ADMIN_ROLE to grant roles");
        grantRole(SCHEME_ADMIN_ROLE, account);
    }

    function revokeSchemeAdminRole(address account, bytes32 schemeId) external override {
        require(schemeExists(schemeId), "Scheme ID does not exist");
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Must have DEFAULT_ADMIN_ROLE to revoke roles");
        revokeRole(SCHEME_ADMIN_ROLE, account);
    }

    function isSchemeAdmin(address account, bytes32 schemeId) external view override returns (bool) {
        return hasRole(SCHEME_ADMIN_ROLE, account) && schemeExists(schemeId);
    }

    function getScheme(bytes32 schemeId) external view override returns (bytes32, bytes32, bool) {
        Scheme storage scheme = schemes[schemeId];
        return (scheme.name, scheme.description, scheme.merkleRoot != "");
    }

    function schemeExists(bytes32 schemeId) private view returns (bool) {
        return schemes[schemeId].id == schemeId;
    }
}

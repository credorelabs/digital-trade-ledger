//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

interface ISchemeManagement {
    function addScheme(bytes32 schemeId, bytes32 schemeName, bytes32 description, bytes32 merkleRoot) external;
    function updateScheme(bytes32 schemeId, bytes32 name, bytes32 description, bytes32 merkleRoot) external;
    function removeScheme(bytes32 schemeId) external;
    function grantSchemeAdminRole(address account, bytes32 schemeId) external;
    function revokeSchemeAdminRole(address account, bytes32 schemeId) external;
    function isSchemeAdmin(address account, bytes32 schemeId) external view returns (bool);
    function getScheme(bytes32 schemeId) external view returns (bytes32, bytes32, bool);    
}
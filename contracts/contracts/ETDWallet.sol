//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interfaces/ITitleEscrow.sol";
import "./interfaces/ETDWalletErrors.sol";

/**
 * @title ETDWallet
 * @dev The ETDWallet contract manages the operations related to the title document transfer, including nominations, transfers of beneficiaries and holders, surrendering, and shredding of title documents. 
 * The contract utilizes OpenZeppelin libraries for access control, reentrancy protection, and utility functions. 
 * It supports role-based access control for attorney administrators and implements nonce-based replay protection for authorized actions.
 * Additionally, the contract provides functionality for verifying signatures, ensuring secure and authenticated interactions with external systems and entities.
 * Note: This contract is intended for use within the context of title document operations and may require integration with external systems and interfaces.
 */
contract ETDWallet  is AccessControl, ETDWalletErrors, Initializable, ReentrancyGuard {
    using Address for address;
    using ECDSA for bytes32;

    address public owner;
    address public attorney;
    bytes32 public constant ATTORNEY_ADMIN_ROLE = keccak256("ATTORNEY_ADMIN_ROLE");
    mapping(address => uint256) private nonces;

    event AttorneyChanged(address indexed oldAttorney, address indexed newAttorney);
    event HolderTransfer(address indexed holder, address indexed newHolder);
    event BeneficiaryTransfer(address indexed beneficiary, address indexed nominee);

    /**
        * @notice Initializes the ETD Wallet contract with the owner address and sets up attorney
        * @param _owner The address of the ETD wallet owner
    */
    function initialize(address _attorney, address _owner) public virtual initializer {
        _setupRole(ATTORNEY_ADMIN_ROLE, _attorney);
        __ETDWallet_init(_attorney, _owner);
    }

    /**
    * @notice Initializes the ETDWallet contract with the owner address and sets up attorney
    */
    function __ETDWallet_init(address _attorney, address _owner) internal virtual onlyInitializing {
        if ( _attorney == address(0) || _owner == address(0) ){
                revert InvalidOperationToZeroAddress();
        }
        attorney = _attorney;
        owner = _owner;
    }

    constructor() initializer {}

    function nominate(
        address _nominee,
        address _titleEscrow, 
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
    ) 
    public onlyRole(ATTORNEY_ADMIN_ROLE) 
    {
        if ( _titleEscrow == address(0) || _nominee == address(0)){
            revert InvalidOperationToZeroAddress();
        }
        if (_signature.length != 65){
            revert InvalidSignature();
        }

        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }
        
        ITitleEscrow(_titleEscrow).nominate(_nominee);
    }

    /**
     * @notice Set the current attorney to a new address.
     * @param newAttorney The address of the new attorney.
    */
    function setAttorney(address newAttorney) public onlyRole(ATTORNEY_ADMIN_ROLE){
      _setupRole(ATTORNEY_ADMIN_ROLE, newAttorney);
      attorney = newAttorney;
      emit AttorneyChanged(msg.sender, newAttorney);
    }

    function transferBeneficiary(
        address _titleEscrow,
        address _nominee, 
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
    )
    public onlyRole(ATTORNEY_ADMIN_ROLE)
    {
        if ( _titleEscrow == address(0) || _nominee == address(0)){
            revert InvalidOperationToZeroAddress();
        }
        
        if (_signature.length != 65){
            revert InvalidSignature();
        }

        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }
        
        ITitleEscrow(_titleEscrow).transferBeneficiary(_nominee);        
    }

    function transferHolder(
        address _titleEscrow,
        address _newHolder, 
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
        ) 
        public onlyRole(ATTORNEY_ADMIN_ROLE) 
        {
        if ( _titleEscrow == address(0) || _newHolder == address(0)){
            revert InvalidOperationToZeroAddress();
        }
        
        if (_signature.length != 65){
            revert InvalidSignature();
        }
  
        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }
        
        ITitleEscrow(_titleEscrow).transferHolder(_newHolder);
    }

    function transferOwners(
        address _titleEscrow,
        address _nominee, 
        address _newHolder,
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
    )
    public onlyRole(ATTORNEY_ADMIN_ROLE) 
    {
        if ( _titleEscrow == address(0) || _nominee == address(0) || _newHolder == address(0) ){
            revert InvalidOperationToZeroAddress();
        }
        
        if (_signature.length != 65){
            revert InvalidSignature();
        }
  
        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }
        ITitleEscrow(_titleEscrow).transferOwners(_nominee, _newHolder);
    }

    function surrender(
        address _titleEscrow,
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
    ) 
    public onlyRole(ATTORNEY_ADMIN_ROLE)
    {
        if ( _titleEscrow == address(0) ){
            revert InvalidOperationToZeroAddress();
        }
        
        if (_signature.length != 65){
            revert InvalidSignature();
        }
  
        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }

        ITitleEscrow(_titleEscrow).surrender();
    }

    function shred(
        address _titleEscrow,
        bytes memory _data, 
        bytes calldata _signature, 
        uint256 _nonce
    ) 
    public onlyRole(ATTORNEY_ADMIN_ROLE)
    {
        if ( _titleEscrow == address(0) ){
            revert InvalidOperationToZeroAddress();
        }
        
        if (_signature.length != 65){
            revert InvalidSignature();
        }
  
        if(_nonce != nonces[owner]){
            revert InvalidNonce();
        }
        
        nonces[owner]++;
        
        if(!_verifyApprover(owner, _data, _signature)){
            revert InvalidSignature();
        }

        ITitleEscrow(_titleEscrow).shred();
    }

    function nonce(address _user) external view returns (uint256) {
        if ( _user == address(0) ){
            revert InvalidOperationToZeroAddress();
        }
        return  nonces[_user];
    }
    /**
     * @dev Verifies the transfer of holder using provided parameters and signature.
     * @param aprover The current holder's address.
     * @param data Data associated with the transfer.
     * @param signature The signature to verify the transfer.
     * @return A boolean indicating if the signature matches the current holder's address.
     * @notice This function is private and is intended for internal use within the contract.
    */
    function _verifyApprover(
        address aprover,
        bytes memory data,
        bytes memory signature
    ) private pure returns (bool) {
        bytes32 messageHash = getApprovalHash(data);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == aprover;
    }
    
    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (sig.length != 65){
            revert InvalidSignature();
        }

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    function getEthSignedMessageHash(
        bytes32 _messageHash
    ) private pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    /**
     * @dev Computes and returns the hash of the transfer holder parameters.
     * @param data Data associated with the transfer.
     * @return A bytes32 hash representing the combination of input parameters.
     * @notice This function is public and pure, ensuring it doesn't modify or interact with the contract's state.
    */
    function getApprovalHash(
        bytes memory data
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(data));
    }
}

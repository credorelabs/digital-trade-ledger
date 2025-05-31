// SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)

pragma solidity >=0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./interfaces/ITitleFlow.sol";
import "./interfaces/ITitleEscrowV2.sol";
import "./interfaces/TitleEscrowErrorsV2.sol";

contract TitleFlow is ITitleFlow, AccessControl, TitleEscrowErrorsV2, Initializable, ReentrancyGuard, IERC721Receiver{
    using Address for address;
    using ECDSA for bytes32;

    address public owner; // Wallet owner who signs actions
    address public attorney; // Admin relayer
    bytes32 public constant ATTORNEY_ADMIN_ROLE = keccak256("ATTORNEY_ADMIN_ROLE");
    mapping(address => mapping(address => uint256)) private nonces; // titleEscrow => owner => nonce

    // Events from ITitleEscrowV2
    event TokenReceived(address indexed beneficiary, address indexed holder, bool indexed isMinting, address registry, uint256 tokenId, bytes remark);
    event Nomination(address indexed prevNominee, address indexed nominee, address registry, uint256 tokenId, bytes remark);
    event BeneficiaryTransfer(address indexed fromBeneficiary, address indexed toBeneficiary, address registry, uint256 tokenId, bytes remark);
    event HolderTransfer(address indexed fromHolder, address indexed toHolder, address registry, uint256 tokenId, bytes remark);
    event OwnersTransferred(address indexed titleEscrow, address indexed nominee, address indexed newHolder);
    event ReturnToIssuer(address indexed caller, address registry, uint256 tokenId, bytes remark);
    event Shred(address registry, uint256 tokenId, bytes remark);
    event RejectTransferOwners(address indexed fromBeneficiary, address indexed toBeneficiary, address indexed fromHolder, address toHolder, address registry, uint256 tokenId, bytes remark);
    event RejectTransferBeneficiary(address indexed fromBeneficiary, address indexed toBeneficiary, address registry, uint256 tokenId, bytes remark);
    event RejectTransferHolder(address indexed fromHolder, address indexed toHolder, address registry, uint256 tokenId, bytes remark);
    event AttorneyChanged(address indexed oldAttorney, address indexed newAttorney);

    //constructor() initializer {}
    constructor() {}

    /// @notice Initializes the contract with attorney and owner addresses
    function initialize(address _attorney, address _owner) override public virtual initializer {
        _setupRole(ATTORNEY_ADMIN_ROLE, _attorney);
        __TitleFlow_init(_attorney, _owner);
    }

    function __TitleFlow_init(address _attorney, address _owner) internal onlyInitializing {
        if (_attorney == address(0) || _owner == address(0)) revert InvalidOperationToZeroAddress();
        attorney = _attorney;
        owner = _owner;
    }

    /// @notice Updates the attorney, revoking the old one's role
    function setAttorney(address newAttorney) override public onlyRole(ATTORNEY_ADMIN_ROLE) {
        if (newAttorney == address(0)) revert InvalidOperationToZeroAddress();
        address oldAttorney = attorney;
        _setupRole(ATTORNEY_ADMIN_ROLE, newAttorney);
        revokeRole(ATTORNEY_ADMIN_ROLE, oldAttorney);
        attorney = newAttorney;
        emit AttorneyChanged(oldAttorney, newAttorney);
    }

    // IERC721Receiver implementation
    function onERC721Received(address, address, uint256, bytes calldata) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // Gasless ITitleEscrowV2 methods
    function nominate(address _nominee, bytes calldata _remark, address _titleEscrow, bytes memory _data, bytes calldata _signature, uint256 _nonce)
        override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant
    {
        _verifyAction(_titleEscrow, _nominee, address(0), _data, _signature, _nonce, ActionType.Nominate);
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.nominate.selector, _nominee, _remark));
        if (!success) revert ActionFailed("Nominate failed");
        nonces[_titleEscrow][owner]++;
        emit Nomination(address(0), _nominee, ITitleEscrowV2(_titleEscrow).registry(), ITitleEscrowV2(_titleEscrow).tokenId(), _remark);
    }

    function transferBeneficiary(address _nominee, bytes calldata _remark, address _titleEscrow, bytes memory _data, bytes calldata _signature, uint256 _nonce)
        override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant
    {
        _verifyAction(_titleEscrow, _nominee, address(0), _data, _signature, _nonce, ActionType.BeneficiaryTransfer);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        address fromBeneficiary = escrow.beneficiary();
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.transferBeneficiary.selector, _nominee, _remark));
        if (!success) revert ActionFailed("Beneficiary transfer failed");
        nonces[_titleEscrow][owner]++;
        emit BeneficiaryTransfer(fromBeneficiary, _nominee, escrow.registry(), escrow.tokenId(), _remark);
    }

    function transferHolder(
        address _newHolder,
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), _newHolder, _data, _signature, _nonce, ActionType.HolderTransfer);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        address fromHolder = escrow.holder(); // Fetch before transfer
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.transferHolder.selector, _newHolder, _remark));
        if (!success) revert ActionFailed("Holder transfer failed");
        nonces[_titleEscrow][owner]++;
        emit HolderTransfer(fromHolder, _newHolder, escrow.registry(), escrow.tokenId(), _remark);
    }

    function transferOwners(address _nominee, address _newHolder, bytes calldata _remark, address _titleEscrow, bytes memory _data, bytes calldata _signature, uint256 _nonce)
        override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant
    {
        _verifyAction(_titleEscrow, _nominee, _newHolder, _data, _signature, _nonce, ActionType.OwnersTransfer);
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.transferOwners.selector, _nominee, _newHolder, _remark));
        if (!success) revert ActionFailed("Owners transfer failed");
        nonces[_titleEscrow][owner]++;
        emit OwnersTransferred(_titleEscrow, _nominee, _newHolder);
    }

    function rejectTransferBeneficiary(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), address(0), _data, _signature, _nonce, ActionType.RejectBeneficiary);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        address toBeneficiary = escrow.nominee(); // Fetch before rejection
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.rejectTransferBeneficiary.selector, _remark));
        if (!success) revert ActionFailed("Reject beneficiary failed");
        nonces[_titleEscrow][owner]++;
        emit RejectTransferBeneficiary(escrow.beneficiary(), toBeneficiary, escrow.registry(), escrow.tokenId(), _remark);
    }

    function rejectTransferHolder(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), address(0), _data, _signature, _nonce, ActionType.RejectHolder);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        address toHolder = escrow.prevHolder(); // Fetch before rejection
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.rejectTransferHolder.selector, _remark));
        if (!success) revert ActionFailed("Reject holder failed");
        nonces[_titleEscrow][owner]++;
        _emitRejectTransferHolder(escrow, toHolder, _remark);
    }

    function _emitRejectTransferHolder(ITitleEscrowV2 escrow, address toHolder, bytes calldata _remark) internal {
        emit RejectTransferHolder(
            escrow.holder(),
            toHolder,
            escrow.registry(),
            escrow.tokenId(),
            _remark
        );
    }
    
    function rejectTransferOwners(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), address(0), _data, _signature, _nonce, ActionType.RejectOwners);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        address nominee = escrow.nominee(); // Capture nominee before rejection
        address holder = escrow.holder();   // Capture holder before rejection
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.rejectTransferOwners.selector, _remark));
        if (!success) revert ActionFailed("Reject owners failed");
        nonces[_titleEscrow][owner]++;
        _emitRejectTransferOwners(escrow, nominee, holder, _remark);
    }

    function _emitRejectTransferOwners(
        ITitleEscrowV2 escrow,
        address nominee,
        address holder,
        bytes calldata _remark
    ) internal {
        emit RejectTransferOwners(
            escrow.beneficiary(),
            nominee,
            holder,
            address(0),
            escrow.registry(),
            escrow.tokenId(),
            _remark
        );
    }

    function returnToIssuer(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), address(0), _data, _signature, _nonce, ActionType.ReturnToIssuer);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.returnToIssuer.selector, _remark));
        if (!success) revert ActionFailed("Return to issuer failed");
        nonces[_titleEscrow][owner]++;
        _emitReturnToIssuer(escrow, msg.sender, _remark);
    }

    function _emitReturnToIssuer(ITitleEscrowV2 escrow, address caller, bytes calldata _remark) internal {
        emit ReturnToIssuer(caller, escrow.registry(), escrow.tokenId(), _remark);
    }

    function shred(
        bytes calldata _remark,
        address _titleEscrow,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce
    ) override public onlyRole(ATTORNEY_ADMIN_ROLE) nonReentrant {
        _verifyAction(_titleEscrow, address(0), address(0), _data, _signature, _nonce, ActionType.Shred);
        ITitleEscrowV2 escrow = ITitleEscrowV2(_titleEscrow);
        (bool success, ) = _titleEscrow.call(abi.encodeWithSelector(ITitleEscrowV2.shred.selector, _remark));
        if (!success) revert ActionFailed("Shred failed");
        nonces[_titleEscrow][owner]++;
        _emitShred(escrow, _remark);
    }

    function _emitShred(ITitleEscrowV2 escrow, bytes calldata _remark) internal {
        emit Shred(escrow.registry(), escrow.tokenId(), _remark);
    }

    // View functions (not gasless, direct calls to ITitleEscrowV2)
    function beneficiary(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).beneficiary();
    }

    function holder(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).holder();
    }

    function prevBeneficiary(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).prevBeneficiary();
    }

    function prevHolder(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).prevHolder();
    }

    function active(address _titleEscrow) override external view returns (bool) {
        return ITitleEscrowV2(_titleEscrow).active();
    }

    function nominee(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).nominee();
    }

    function registry(address _titleEscrow) override external view returns (address) {
        return ITitleEscrowV2(_titleEscrow).registry();
    }

    function tokenId(address _titleEscrow) override external view returns (uint256) {
        return ITitleEscrowV2(_titleEscrow).tokenId();
    }

    function isHoldingToken(address _titleEscrow) override external returns (bool) {
        return ITitleEscrowV2(_titleEscrow).isHoldingToken();
    }

    enum ActionType { Nominate, BeneficiaryTransfer, HolderTransfer, OwnersTransfer, RejectBeneficiary, RejectHolder, RejectOwners, ReturnToIssuer, Shred }

    function _isContract(address _addr) private view returns (bool) {
        return _addr.code.length > 0;
    }

    /// @dev Verifies action parameters and signature, does not increment nonce
    function _verifyAction(
        address _titleEscrow,
        address _nominee,
        address _newHolder,
        bytes memory _data,
        bytes calldata _signature,
        uint256 _nonce,
        ActionType action
    ) private {
        if (_titleEscrow == address(0) || !_isContract(_titleEscrow)) revert InvalidOperationToZeroAddress();
        if ((action == ActionType.Nominate || action == ActionType.BeneficiaryTransfer) && _nominee == address(0)) 
            revert InvalidOperationToZeroAddress();
        if (action == ActionType.HolderTransfer && _newHolder == address(0)) 
            revert InvalidOperationToZeroAddress();
        if (action == ActionType.OwnersTransfer && (_nominee == address(0) || _newHolder == address(0))) 
            revert InvalidOperationToZeroAddress();
        if (_signature.length != 65) revert InvalidSignatureLength();
        if (_nonce != nonces[_titleEscrow][owner]) revert InvalidNonce();

        bytes memory expectedData = abi.encode(_titleEscrow, _nominee, _newHolder, _nonce, uint8(action));
        if (!_verifySignature(owner, expectedData, _signature)) revert InvalidSigner();
    }

    function nonce(address _titleEscrow, address _user) override external view returns (uint256) {
        if (_titleEscrow == address(0) || _user == address(0)) revert InvalidOperationToZeroAddress();
        return nonces[_titleEscrow][_user];
    }

    function _verifySignature(address approver, bytes memory data, bytes memory signature) private pure returns (bool) {
        bytes32 messageHash = keccak256(data);
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        address signer = ECDSA.recover(ethSignedHash, signature);
        if (signer == address(0)) revert InvalidSignature();
        return signer == approver;
    }

    // function _verifyApprover(address approver, bytes memory data, bytes memory signature) private pure returns (bool) {
    //     bytes32 messageHash = keccak256(abi.encodePacked(data));
    //     bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    //     address signer = recoverSigner(ethSignedMessageHash, signature);
    //     return signer != address(0) && signer == approver;
    // }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (sig.length != 65) revert InvalidSignatureLength();
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function getApprovalHash(bytes memory data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(data));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

}
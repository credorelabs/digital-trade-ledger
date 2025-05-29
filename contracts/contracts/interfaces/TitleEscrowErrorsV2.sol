// SPDX-License-Identifier: Apache-2.0
// pragma solidity ^0.8.20;
pragma solidity >=0.8.0;

interface TitleEscrowErrorsV2 {
  error CallerNotBeneficiary();

  error CallerNotHolder();

  error TitleEscrowNotHoldingToken();

  error RegistryContractPaused();

  error InactiveTitleEscrow();

  error InvalidTokenId(uint256 tokenId);

  error InvalidRegistry(address registry);

  error EmptyReceivingData();

  error InvalidTokenTransferToZeroAddressOwners(address beneficiary, address holder);

  error TargetNomineeAlreadyBeneficiary();

  error NomineeAlreadyNominated();

  error InvalidTransferToZeroAddress();

  error InvalidNominee();

  error RecipientAlreadyHolder();

  error TokenNotReturnedToIssuer();

  error RemarkLengthExceeded();

  error DualRoleRejectionRequired();

  error InvalidOperationToZeroAddress();

  error InvalidSignatureLength();

  error InvalidSigner();

  error InvalidNonce();

  error ActionFailed(string reason);

  error InvalidAddress();

  error InvalidSignature();
}
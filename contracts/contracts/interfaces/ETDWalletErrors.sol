//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

interface ETDWalletErrors {
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

  error TokenNotSurrendered();

  error CallerNotAttorney();

  error FirstTimeAttorneyAlreadySet(address attorney);

  error SignerNotHolder(address holder);

  error SignerNotBeneficiary(address beneficiary);

  error InvalidNonce();

  error InvalidTradeTrustTitleEscrow(address titleEscrow);

  error InvalidOperationToZeroAddress();

  error InvalidSignature();
}
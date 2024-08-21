//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

interface IETDWalletFactory {
  event ETDWalletCreated(address indexed attorney, address indexed owner);

  function implementation() external view returns (address);

  /**
   * @notice Creates a new clone of the ETDWallet contract and initializes it with the sender's address
   * @dev The function will revert if it is called by an EOA.
   * @param owner The ID of the token.
   * @return The address of the newly created ETDWallet contract.
   */
  function create(address owner) external returns (address);

  /**
   * @notice Returns the address of a ETDWallet contract that would be created with the provided owner address
   * @param owner The address of the owner.
   * @return The address of the ETDWallet contract.
   */
  function getAddress(address owner) external view returns (address);
}

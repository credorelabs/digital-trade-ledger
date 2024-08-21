// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/**
 * @title ITitleEscrow
 * @notice Interface for TitleEscrow contract. The TitleEscrow contract represents a title escrow for transferable records.
 * @dev Inherits from IERC721Receiver.
 */
interface ITitleEscrow{
  /**
   * @notice Allows the beneficiary to nominate a new beneficiary
   * @dev The nominated beneficiary will need to be transferred by the holder to become the actual beneficiary
   * @param nominee The address of the nominee
   */
  function nominate(address nominee) external;

  /**
   * @notice Allows the holder to transfer the beneficiary role to the nominated beneficiary or to themselves
   * @param nominee The address of the new beneficiary
   */
  function transferBeneficiary(address nominee) external;

  /**
   * @notice Allows the holder to transfer their role to another address
   * @param newHolder The address of the new holder
   */
  function transferHolder(address newHolder) external;

  /**
   * @notice Allows for the simultaneous transfer of both beneficiary and holder roles
   * @param nominee The address of the new beneficiary
   * @param newHolder The address of the new holder
   */
  function transferOwners(address nominee, address newHolder) external;


  /**
   * @notice Allows the beneficiary and holder to surrender the token back to the registry
   */
  function surrender() external;

  /**
   * @notice Allows the registry to shred the TitleEscrow by marking it as inactive and reset the beneficiary and holder addresses
   */
  function shred() external;
}
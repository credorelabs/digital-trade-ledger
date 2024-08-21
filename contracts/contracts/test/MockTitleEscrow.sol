//SPDX-License-Identifier: GPL-3.0-or-later
// Author: Credore (Trustless Private Limited)
pragma solidity >=0.8.0;

import "../interfaces/ITitleEscrow.sol";

contract TitleEscrowTest  is ITitleEscrow {
    address public holder;
    address public nominee;
    address public beneficiary;

    event HolderTransfer(address indexed holder, address indexed newHolder);

    function transferHolder(address _newHolder) override public{
        address oldHolder = holder;
        holder = _newHolder;
        emit HolderTransfer(oldHolder, holder);
    }

    function transferBeneficiary(address _newBeneficiary) override public {
        beneficiary = _newBeneficiary;
    }

    function nominate(address _nominee) override external{
        nominee = _nominee;
    }

    function transferOwners(address _nominee, address _newHolder) override external{
        transferBeneficiary(_nominee);
        transferHolder(_newHolder);
    }

    function surrender() external override virtual{
        nominee = address(0);
    }

    function shred() external override virtual{
        beneficiary = address(0);
        holder = address(0);
    }
}

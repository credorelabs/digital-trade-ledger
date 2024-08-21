import { AccountId, Client, ContractCreateFlow, PrivateKey, ContractFunctionParameters } from "@hashgraph/sdk";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config(); // Load environment variables from .env file

function getEnvVariable(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Environment variable ${name} is not defined.`);
  }
  return value;
}

async function main() {
  try {
    const accountId = getEnvVariable("HEDERA_ACCOUNT_ID");
    const privateKey = getEnvVariable("HEDERA_PRIVATE_KEY");
    const publicUrl = getEnvVariable("PUBLIC_URL");

    console.log("Account ID", accountId);

    const operatorId = AccountId.fromString(accountId);
    const operatorKey = PrivateKey.fromStringECDSA(privateKey);
    const client = Client.forTestnet().setOperator(operatorId, operatorKey);

    // Read the Verifier smart contract bytecode
    const contractVerifierByteCode = fs.readFileSync(path.join(publicUrl, "___contracts_Main_sol_Verifier.bin"));

    // Create the Verifier smart contract
    const createVerifierContract = new ContractCreateFlow()
      .setGas(150000) // Increase if revert
      .setBytecode(contractVerifierByteCode); // Contract bytecode

    const createVerifierContractTx = await createVerifierContract.execute(client);
    const createVerifierContractRx = await createVerifierContractTx.getReceipt(client);
    const contractVerifierId = createVerifierContractRx.contractId;

    if (!contractVerifierId) {
      throw new Error("Failed to create Verifier contract");
    }

    console.log(`Verifier contract created with ID: ${contractVerifierId.toSolidityAddress()} \n`);

    // Read the ZKApp smart contract bytecode
    const contractZKAppByteCode = fs.readFileSync(path.join(publicUrl, "___contracts_ZkApp_sol_ZkApp.bin"));

    // Create the ZKApp smart contract
    const createZKAppContract = new ContractCreateFlow()
      .setGas(150000) // Increase if revert
      .setBytecode(contractZKAppByteCode) // Contract bytecode
      .setConstructorParameters(new ContractFunctionParameters().addString(contractVerifierId.toSolidityAddress()));

    const createZKAppContractTx = await createZKAppContract.execute(client);
    const createZKAppContractRx = await createZKAppContractTx.getReceipt(client);
    const contractZKAppId = createZKAppContractRx.contractId;

    if (!contractZKAppId) {
      throw new Error("Failed to create ZKApp contract");
    }

    console.log(`ZKApp contract created with ID: ${contractZKAppId.toSolidityAddress()} \n`);

    // Read the DLPC smart contract bytecode
    const contractLookUpByteCode = fs.readFileSync(path.join(publicUrl, "___contracts_Dlpc_sol_DLPC.bin"));

    // Create the DLPC smart contract
    const contractInstantiateTx = new ContractCreateFlow()
      .setGas(150000) // Increase if revert
      .setBytecode(contractLookUpByteCode) // Contract bytecode
      .setConstructorParameters(
        new ContractFunctionParameters()
          .addString("bea0ea1b-b0bb-44f0-bb78-7a966d8a0620")
          .addUint256(88523130448140787427807155879320149026984723687438622692732647847901138947593)
      );

    const contractInstantiateSubmit = await contractInstantiateTx.execute(client);
    const contractInstantiateRx = await contractInstantiateSubmit.getReceipt(client);
    const contractId = contractInstantiateRx.contractId;

    if (!contractId) {
      throw new Error("Failed to create DLPC contract");
    }

    const contractAddress = contractId.toSolidityAddress();
    console.log(`- The smart contract ID is: ${contractId} \n`);
    console.log(`- The smart contract ID in Solidity format is: ${contractAddress} \n`);
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

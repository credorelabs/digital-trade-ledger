import hre, { network, ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying TitleFlowFactory with the account:", deployer.address);

  console.log("Account balance:", (await deployer.getBalance()).toString());

  // We get the contract to deploy
  const TitleFlowFactory = await ethers.getContractFactory("TitleFlowFactory");
  const titleFlowFactory = await TitleFlowFactory.deploy();
  await titleFlowFactory.deployed();
  console.log(`TitleFlowFactory deployed at: ${titleFlowFactory.address}`)

}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
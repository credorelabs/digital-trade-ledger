import hre, { network, ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  console.log("Account balance:", (await deployer.getBalance()).toString());

  // We get the contract to deploy
  const Verifier = await ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy();
  await verifier.deployed();
  console.log(`verifier deployed at: ${verifier.address}`)
  

  const uri = "";
  const DigitalAssetRegistry__factory = await ethers.getContractFactory("DigitalAssetRegistry");
  const DigitalAssetRegistry = await DigitalAssetRegistry__factory.deploy(uri);
  await DigitalAssetRegistry.deployed();
  console.log(`DigitalAssetRegistry deployed at: ${DigitalAssetRegistry.address}`);

  const MetaTx__factory = await ethers.getContractFactory("MetaTx");
  const MetaTx = await MetaTx__factory.deploy();
  await MetaTx.deployed();
  console.log(`MetaTx deployed at: ${MetaTx.address}`);

  const ZKVerifier__factory = await ethers.getContractFactory("ZKVerifier");
  const ZKVerifier = await ZKVerifier__factory.deploy(verifier.address);
  await ZKVerifier.deployed();
  console.log(`ZKVerifier deployed at: ${ZKVerifier.address}`)

  // Setup
  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
  await sleep(5000);
  await DigitalAssetRegistry.grantRole(await DigitalAssetRegistry.DEFAULT_ADMIN_ROLE(), deployer.address);
  console.log(`DEFAULT_ADMIN_ROLE set`)
  await sleep(5000);
  await DigitalAssetRegistry.grantRole(await DigitalAssetRegistry.TOKEN_ISSUER_ROLE(), deployer.address);
  console.log(`TOKEN_ISSUER_ROLE set`)
  
  

  await sleep(5000);
  await DigitalAssetRegistry.setMetaTxContractAddress(MetaTx.address);
  await sleep(5000);
  console.log(`MetaTx Address set`)
  await MetaTx.setVerifier(verifier.address);
  await sleep(5000);
  console.log(`verifier set in Meta Tx`)
  await MetaTx.setDigitalAssetRegistry(DigitalAssetRegistry.address);
  console.log(`DigitalAssetRegistry set in Meta Tx`)

  await sleep(5000);
  
  // Remove the commented code to verify the deployed code automatically.
  // try {
  //   console.log("\nMetaTx etherscan verification in progress...");
  //   //await MetaTx.deployTransaction.wait(6);
  //   await hre.run("verify:verify", {
  //     network: network.name,
  //     address: '0x310f24231AD1AbDEF27C85567a76D0d8D90081ED',
  //     constructorArguments: ['0x6Fa7eac980A4dB5Fc79E2cfCbFeaaC71F5E19f5D']
  //   });
  //   console.log("Verifier etherscan verification done. ✅");
  // } catch (error) {
  //   console.error(`verification failed: ${error}`);
  // }

}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
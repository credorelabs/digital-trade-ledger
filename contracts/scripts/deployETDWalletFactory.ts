import hre, { network, ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying ETDWalletFactory with the account:", deployer.address);

  console.log("Account balance:", (await deployer.getBalance()).toString());

  // We get the contract to deploy
  // const ETDWalletFactory = await ethers.getContractFactory("ETDWalletFactory");
  // const etdWalletFactory = await ETDWalletFactory.deploy();
  // await etdWalletFactory.deployed();
  // console.log(`ETDWalletFactory deployed at: ${etdWalletFactory.address}`)
  
  // const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
  

  // await sleep(50000);  
  
  // Remove the commented code to verify the deployed code automatically.
  try {
    console.log("\ETDWalletFactory etherscan verification in progress...");
    
    await hre.run("verify:verify", {
      network: network.name,
      address: '0x389e46A3147f3E2F58b411018Af8495Ac37EA9E2'//etdWalletFactory.address
    });
    console.log("ETDWalletFactory etherscan verification done. ✅");
  } catch (error) {
    console.error(`verification failed: ${error}`);
  }

}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

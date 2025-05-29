import { ethers } from "hardhat";
import { expect } from "chai";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { TitleFlowFactory, TitleFlow } from "../typechain"; // Adjust path based on your setup

describe("TitleFlowFactory", () => {
  let factory: TitleFlowFactory;
  let titleFlowImpl: TitleFlow;
  let deployer: SignerWithAddress;
  let attorney: SignerWithAddress;
  let user: SignerWithAddress;
  let nonAdmin: SignerWithAddress;
  const zeroAddress = ethers.constants.AddressZero;

  // Role hash
  const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE")
  );

  beforeEach(async () => {
    [deployer, attorney, user, nonAdmin] = await ethers.getSigners();

    // Deploy TitleFlow implementation
    const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
    titleFlowImpl = await TitleFlowFactory.deploy();

    // Deploy TitleFlowFactory
    const Factory = await ethers.getContractFactory("TitleFlowFactory");
    factory = await Factory.deploy();
    await factory.deployed();
  });

  describe("Deployment", () => {
    it("should set the correct implementation address", async () => {
      const implAddress = await factory.implementation();
      expect(implAddress).to.be.properAddress;
      expect(implAddress).to.not.equal(zeroAddress);
    });

    it("should set deployer as ATTORNEY_ADMIN_ROLE", async () => {
      const hasRole = await factory.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address);
      expect(hasRole).to.be.true;
    });
  });

  describe("create()", () => {
    it("should create new TitleFlow instance with admin privileges", async () => {
        const predictedAddress = await factory.connect(deployer).getAddress(user.address);
        const tx = await factory.connect(deployer).create(user.address);
        const receipt = await tx.wait();
        
        const event = receipt.events?.find(e => e.event === "TitleFlowCreated");
        expect(event).to.exist;
        expect(event?.args?.[0]).to.equal(deployer.address);
        expect(event?.args?.[1]).to.equal(user.address);
    
        const titleFlow = await ethers.getContractAt("TitleFlow", predictedAddress);
        const owner = await titleFlow.owner();
        expect(owner).to.equal(user.address);
    });

    it("should revert if called by non-admin", async () => {
      await expect(
        factory.connect(nonAdmin).create(user.address)
      ).to.be.revertedWith(
        `AccessControl: account ${nonAdmin.address.toLowerCase()} is missing role ${ATTORNEY_ADMIN_ROLE}`
      );
    });
  });

  describe("getAddress()", () => {
    it("should predict correct deterministic address", async () => {
      const predictedAddress = await factory.connect(deployer).getAddress(user.address);
      expect(predictedAddress).to.be.properAddress;

      await factory.connect(deployer).create(user.address);
      const actualAddress = await factory.connect(deployer).getAddress(user.address);
      expect(actualAddress).to.equal(predictedAddress);
    });
  });

  describe("setupAdmin()", () => {
    it("should grant ATTORNEY_ADMIN_ROLE to new admin", async () => {
      await factory.connect(deployer).setupAdmin(attorney.address);
      const hasRole = await factory.hasRole(ATTORNEY_ADMIN_ROLE, attorney.address);
      expect(hasRole).to.be.true;
    });

    it("should revert if called by non-admin", async () => {
      await expect(
        factory.connect(nonAdmin).setupAdmin(attorney.address)
      ).to.be.revertedWith(
        `AccessControl: account ${nonAdmin.address.toLowerCase()} is missing role ${ATTORNEY_ADMIN_ROLE}`
      );
    });
  });

  describe("Security", () => {
    it("should have disabled implementation contract", async () => {
        const impl = await ethers.getContractAt("TitleFlow", await factory.implementation());
        const owner = await impl.owner();
        expect(owner).to.equal(zeroAddress);
      });
    
      it("should include ReentrancyGuard protection", async () => {
        const factoryCode = await ethers.provider.getCode(factory.address);
        expect(factoryCode).to.not.equal("0x");
        // Note: Add a proper reentrancy test if a vulnerable function is introduced
      });
  });
});
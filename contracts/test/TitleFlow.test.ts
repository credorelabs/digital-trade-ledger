import { ethers } from "hardhat";
import { expect } from "chai";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { TitleFlow, TitleEscrowMock, MaliciousTitleEscrow } from "../typechain"; // Adjust path

describe("TitleFlow", () => {
  let titleFlow: TitleFlow;
  let titleEscrowMock: TitleEscrowMock;
  let maliciousEscrow: MaliciousTitleEscrow;
  let deployer: SignerWithAddress;
  let owner: SignerWithAddress;
  let nominee: SignerWithAddress;
  let nonAdmin: SignerWithAddress;
  let unauthorized: SignerWithAddress; 

  const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
  const zeroAddress = ethers.constants.AddressZero;

  beforeEach(async () => {
    [deployer, owner, nominee, nonAdmin, unauthorized] = await ethers.getSigners();

    const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
    titleEscrowMock = await TitleEscrowMockFactory.deploy();
    await titleEscrowMock.deployed();
    const MaliciousEscrow = await ethers.getContractFactory("MaliciousTitleEscrow");

    const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
    titleFlow = await TitleFlowFactory.deploy();
    await titleFlow.deployed();

    maliciousEscrow = await MaliciousEscrow.deploy(titleFlow.address);
    await titleFlow.initialize(deployer.address, owner.address);

    expect(await titleFlow.attorney()).to.equal(deployer.address);
    expect(await titleFlow.owner()).to.equal(owner.address);
    expect(await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address)).to.be.true;

    await titleEscrowMock.setState(
        owner.address,
        deployer.address,
        zeroAddress,
        zeroAddress,
        zeroAddress,
        true,
        titleEscrowMock.address,
        42
    );

    expect(await titleEscrowMock.beneficiary()).to.equal(owner.address);
    // Verify initial holder
    expect(await titleEscrowMock.holder()).to.equal(deployer.address);
  });

  describe("nominate()", () => {
    it("should successfully nominate with valid signature and emit Nomination event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));

      const tx = await titleFlow.connect(deployer).nominate(
        nominee.address,
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();

      const event = receipt.events?.find(e => e.event === "Nomination");
      expect(event).to.exist;
      expect(event?.args?.prevNominee).to.equal(zeroAddress);
      expect(event?.args?.nominee).to.equal(nominee.address);
      expect(event?.args?.registry).to.equal(await titleEscrowMock.registry());
      expect(event?.args?.tokenId).to.equal(await titleEscrowMock.tokenId());
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));

      const newNonce = await titleFlow.nonce(titleEscrowMock.address, owner.address);
      expect(newNonce).to.equal(1);

      expect(await titleEscrowMock.nominee()).to.equal(nominee.address);
    });

    it("should revert if called by non-admin", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

      await expect(
        titleFlow.connect(nonAdmin).nominate(
          nominee.address,
          remark,
          titleEscrowMock.address,
          actionData,
          signature,
          nonce
        )
      ).to.be.revertedWith(
        `AccessControl: account ${nonAdmin.address.toLowerCase()} is missing role ${ATTORNEY_ADMIN_ROLE}`
      );
    });

    it("should succeed with non-empty remark", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));

      const tx = await titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", signature, nonce);
    
      const receipt = await tx.wait();

      const event = receipt.events?.find(e => e.event === "Nomination");
      expect(event).to.exist;
      expect(event?.args?.prevNominee).to.equal(zeroAddress);
      expect(event?.args?.nominee).to.equal(nominee.address);
      expect(event?.args?.registry).to.equal(await titleEscrowMock.registry());
      expect(event?.args?.tokenId).to.equal(await titleEscrowMock.tokenId());
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));

      const newNonce = await titleFlow.nonce(titleEscrowMock.address, owner.address);
      expect(newNonce).to.equal(1);

      expect(await titleEscrowMock.nominee()).to.equal(nominee.address);
    });

    it("should revert with InvalidNonce if nonce is incorrect", async () => {
      const nonce = 1;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

      await expect(
        titleFlow.connect(deployer).nominate(
          nominee.address,
          remark,
          titleEscrowMock.address,
          actionData,
          signature,
          nonce
        )
      ).to.be.revertedWith("InvalidNonce");
    });

    it("should revert with InvalidSigner if signature is invalid", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const wrongSignature = await nonAdmin.signMessage(ethers.utils.arrayify(messageHash));
      await expect(titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", wrongSignature, nonce))
      .to.be.revertedWith("InvalidSigner");
    });

    it("should revert with signature for wrong contract address", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const wrongContractAddress = ethers.Wallet.createRandom().address;
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [wrongContractAddress, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
      await expect(titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidSigner");
    });

    it("should revert for zero titleEscrow address", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const wrongContractAddress = ethers.Wallet.createRandom().address;
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [wrongContractAddress, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
  
      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, zeroAddress, "0x", signature, nonce)
      ).to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    it("should revert for non-contract titleEscrow", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
  

      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, nonAdmin.address, "0x", signature, nonce)
      ).to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    ///////// Nonce Management
    it("should revert with InvalidNonce if nonce is incorrect", async () => {
      const nonce = 1;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

      await expect(
        titleFlow.connect(deployer).nominate(
          nominee.address,
          remark,
          titleEscrowMock.address,
          actionData,
          signature,
          nonce
        )
      ).to.be.revertedWith("InvalidNonce");
    });

    it("should revert with non-sequential nonce", async function () {
      const nonce = 2;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", signature, nonce)
      ).to.be.revertedWith("InvalidNonce");
    });

    it("should revert with zero nonce after increment", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
      // Perform successful nomination to increment nonce
      await titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", signature, nonce);

      // Attempt nomination with zero nonce again
      const newActionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, 0, 0]
      );
      const newSignature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(newActionData)));

      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", newSignature, 0)
      ).to.be.revertedWith("InvalidNonce");
    });

    ///////// Reentrancy Protection
    it("should revert on reentrant call", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, maliciousEscrow.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));
    
      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, maliciousEscrow.address, "0x", signature, nonce)
      ).to.be.revertedWith("Nominate failed");
    });

    ///////// Edge Cases    
    it("should succeed with large remark", async function () {
      const nonce = 0;
      const largeRemark = ethers.utils.hexlify(ethers.utils.randomBytes(1024));
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

      const tx = await titleFlow.connect(deployer).nominate(nominee.address, largeRemark, titleEscrowMock.address, "0x", signature, nonce);
      const receipt = await tx.wait();

      const event = receipt.events?.find(e => e.event === "Nomination");
      expect(event?.args?.nominee).to.equal(nominee.address);
      expect(event?.args?.remark).to.equal(largeRemark);
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
    });

    it("should revert with invalid signature length", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const invalidSignature = "0x1234"; // <65 bytes

      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", invalidSignature, nonce)
      ).to.be.revertedWith("InvalidSignatureLength");
    });

    it("should revert with maximum nonce value", async function () {
      const maxNonce = ethers.BigNumber.from("2").pow(256).sub(1);
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, maxNonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

      await expect(
        titleFlow.connect(deployer).nominate(nominee.address, remark, titleEscrowMock.address, "0x", signature, maxNonce)
      ).to.be.revertedWith("InvalidNonce");
    });

  });

  describe("transferHolder()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress;
    let owner: SignerWithAddress;
    let newHolder: SignerWithAddress;
  
    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;
  
    beforeEach(async () => {
      [deployer, owner, newHolder] = await ethers.getSigners();
  
      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();
  
      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();
  
      await titleFlow.initialize(deployer.address, owner.address);
  
      await titleEscrowMock.setState(
        owner.address,
        deployer.address,
        zeroAddress,
        zeroAddress,
        zeroAddress,
        true,
        titleEscrowMock.address,
        42
      );
  
      expect(await titleEscrowMock.holder()).to.equal(deployer.address);
    });
  
    it("should successfully transfer holder with valid signature and emit HolderTransfer event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).transferHolder(
        newHolder.address,
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();
  
      const event = receipt.events?.find((e) => e.event === "HolderTransfer");
      expect(event).to.exist;
      expect(event?.args?.fromHolder).to.equal(deployer.address);
      expect(event?.args?.toHolder).to.equal(newHolder.address);
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));
  
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
      expect(await titleEscrowMock.holder()).to.equal(newHolder.address);
    });

    it("should revert for non-attorney caller", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(nonAdmin).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith(`AccessControl: account ${nonAdmin.address.toLowerCase()} is missing role ${ATTORNEY_ADMIN_ROLE}`);
    });

    it("should revert for revoked attorney", async function () {
      await titleFlow.connect(owner).revokeRole(ATTORNEY_ADMIN_ROLE, deployer.address);
  
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const expectedError = `AccessControl: account ${deployer.address.toLowerCase()} is missing role ${await titleFlow.ATTORNEY_ADMIN_ROLE()}`;
      await expect(
        titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce)
      ).to.be.revertedWith(expectedError);
    });

    it("should succeed with empty remark data", async function () {
      const nonce = 0;
      const remark = "0x";
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce);
      const receipt = await tx.wait();
      const event = receipt.events?.find((e) => e.event === "HolderTransfer");
      expect(event?.args?.remark).to.equal(remark);
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
    });

    it("should revert for zero newHolder address", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(zeroAddress, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    it("should revert for zero titleEscrow address", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, zeroAddress, "0x", signature, nonce))
        .to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    it("should revert for non-contract titleEscrow", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, nonAdmin.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    it("should revert with invalid signature", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 1]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidSigner");
    });

    it("should revert with tampered signature", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const wrongHolder = nonAdmin.address;
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, wrongHolder, nonce, 1]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidSigner");
    });
  
    it("should revert with signature for wrong contract address", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const wrongContractAddress = ethers.Wallet.createRandom().address;
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [wrongContractAddress, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 1]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidSigner");
    });

    it("should revert with reused nonce", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce);      
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidNonce");
    });
    
    it("should revert with non-sequential nonce", async function () {
      const nonce = 2;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce))
        .to.be.revertedWith("InvalidNonce");
    });
  
    it("should revert with zero nonce after increment", async function () {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Holder transfer error");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, nonce, 2]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      await titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", signature, nonce);
  
      const newActionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, newHolder.address, 0, 2]
      );
      const newMessageHash = ethers.utils.keccak256(newActionData);
      const newSignature = await owner.signMessage(ethers.utils.arrayify(newMessageHash));
  
      await expect(titleFlow.connect(deployer).transferHolder(newHolder.address, remark, titleEscrowMock.address, "0x", newSignature, 0))
        .to.be.revertedWith("InvalidNonce");
    });

  });

  describe("transferBeneficiary()", () => {
    it("should successfully transfer beneficiary with valid signature and emit BeneficiaryTransfer event", async () => {
        const nonce = 0;
        const remark = ethers.utils.toUtf8Bytes("Beneficiary transfer remark");
        const actionData = ethers.utils.defaultAbiCoder.encode(
          ["address", "address", "address", "address", "uint256", "uint8"],
          [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 1]
        );
        const messageHash = ethers.utils.keccak256(actionData);
        const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
    
        const tx = await titleFlow.connect(deployer).transferBeneficiary(
            nominee.address,
            remark,
            titleEscrowMock.address,
            actionData,
            signature,
            nonce
        );
        const receipt = await tx.wait();
    
        const event = receipt.events?.find((e) => e.event === "BeneficiaryTransfer");
        expect(event).to.exist;
        expect(event?.args?.fromBeneficiary).to.equal(owner.address);
        expect(event?.args?.toBeneficiary).to.equal(nominee.address);
        expect(event?.args?.registry).to.equal(titleEscrowMock.address);
        expect(event?.args?.tokenId).to.equal(42);
        expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));
    
        expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
        expect(await titleEscrowMock.beneficiary()).to.equal(nominee.address);
    });  

    it("should revert when called by unauthorized account without ATTORNEY_ADMIN_ROLE", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, unauthorized.address),
        "Unauthorized account has ATTORNEY_ADMIN_ROLE"
      ).to.be.false;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
  
      // Prepare transfer parameters
      const remark = ethers.utils.toUtf8Bytes("Beneficiary transfer remark");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
  
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      // Attempt transfer by unauthorized account
      await expect(
        titleFlow
          .connect(unauthorized)
          .transferBeneficiary(nominee.address, remark, titleEscrowMock.address, actionData, signature, nonce)
      ).to.be.revertedWith(`AccessControl: account ${unauthorized.address.toLowerCase()} is missing role ${ATTORNEY_ADMIN_ROLE}`)
  
      // Verify state unchanged
      expect(await titleEscrowMock.beneficiary(), "Beneficiary incorrectly changed").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce incorrectly incremented"
      ).to.equal(0);
    });

    it("should revert when nominee is zero address", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
  
      // Prepare transfer parameters with zero address as nominee
      const zeroAddress = ethers.constants.AddressZero;
      const remark = ethers.utils.toUtf8Bytes("Beneficiary transfer remark");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, ethers.constants.AddressZero, nonce, 1]
      );
  
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      // Attempt transfer with zero address nominee
      await expect(
        titleFlow
          .connect(deployer)
          .transferBeneficiary(zeroAddress, remark, titleEscrowMock.address, actionData, signature, nonce)
      ).to.be.revertedWith("InvalidOperationToZeroAddress");
  
      // Verify state unchanged
      expect(await titleEscrowMock.beneficiary(), "Beneficiary incorrectly changed").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce incorrectly incremented"
      ).to.equal(0);
    });

    it("should revert when title escrow is a non-escrow address", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
    
      // Prepare transfer parameters with non-escrow address
      const invalidEscrow = nominee.address; // Random non-escrow address
      const remark = ethers.utils.toUtf8Bytes("Beneficiary transfer remark");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, invalidEscrow, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
          
      // Attempt transfer with invalid escrow address
      await expect(
        titleFlow
          .connect(deployer)
          .transferBeneficiary(nominee.address, remark, invalidEscrow, actionData, signature, nonce)
      ).to.be.revertedWith("InvalidOperationToZeroAddress");
    
      // Verify state unchanged
      expect(await titleEscrowMock.beneficiary(), "Beneficiary incorrectly changed").to.equal(owner.address);
      expect(
        await titleFlow.nonce(invalidEscrow, owner.address),
        "Nonce incorrectly incremented"
      ).to.equal(0);
    });

    it("should revert when signature is invalid", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
    
      // Prepare transfer parameters
      const remark = ethers.utils.toUtf8Bytes("Beneficiary transfer remark");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate invalid signature (signed by nominee instead of owner)
      const messageHash = ethers.utils.keccak256(actionData);
      const invalidSignature = await nominee.signMessage(ethers.utils.arrayify(messageHash));
    
      // Attempt transfer with invalid signature
      await expect(
        titleFlow
          .connect(deployer)
          .transferBeneficiary(nominee.address, remark, titleEscrowMock.address, actionData, invalidSignature, nonce)
      ).to.be.revertedWith("InvalidSigner"); // Adjust to specific error if different
    
      // Verify state unchanged
      expect(await titleEscrowMock.beneficiary(), "Beneficiary incorrectly changed").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce incorrectly incremented"
      ).to.equal(0);
    });

    it("should revert when reusing a nonce after a successful transfer", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Initial nonce incorrect"
      ).to.equal(0);
    
      // Prepare first transfer parameters
      const remark = ethers.utils.toUtf8Bytes("First beneficiary transfer");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature for first transfer
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
    
      // Perform first transfer
      const tx = await titleFlow
        .connect(deployer)
        .transferBeneficiary(nominee.address, remark, titleEscrowMock.address, actionData, signature, nonce);
      await tx.wait();
    
      // Verify first transfer success
      expect(await titleEscrowMock.beneficiary(), "Beneficiary not updated").to.equal(nominee.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce not incremented"
      ).to.equal(1);
    
      // Prepare second transfer with reused nonce
      const secondRemark = ethers.utils.toUtf8Bytes("Second beneficiary transfer remark"); // Fixed: toUtf8 -> toUtf8Bytes
      const secondActionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, deployer.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature with reused nonce
      const secondMessageHash = ethers.utils.keccak256(secondActionData);
      const secondSignature = await owner.signMessage(ethers.utils.arrayify(secondMessageHash));
    
      // Log state before second attempt
      console.log(`Nonce before retry: ${(await titleFlow.nonce(titleEscrowMock.address, owner.address)).toString()}`);
    
      // Attempt second transfer with reused nonce
      await expect(
        titleFlow
          .connect(deployer)
          .transferBeneficiary(deployer.address, secondRemark, titleEscrowMock.address, secondActionData, secondSignature, nonce)
      ).to.be.revertedWith("InvalidNonce"); // Adjust to specific error if needed
    
      // Verify state unchanged after failed attempt
      expect(await titleEscrowMock.beneficiary(), "Beneficiary incorrectly changed").to.equal(nominee.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce incorrectly incremented again"
      ).to.equal(1);
    });

    it("should succeed with empty remark and emit BeneficiaryTransfer event", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Initial nonce incorrect"
      ).to.equal(0);
    
      // Prepare transfer parameters with empty remark
      const remark = ethers.utils.toUtf8Bytes(""); // Empty remark
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
    
      // Perform transfer
      const tx = await titleFlow
        .connect(deployer)
        .transferBeneficiary(nominee.address, remark, titleEscrowMock.address, actionData, signature, nonce);
      const receipt = await tx.wait();
    
      // Verify BeneficiaryTransfer event
      const event = receipt.events?.find((e) => e.event === "BeneficiaryTransfer");
      expect(event, "BeneficiaryTransfer event not emitted").to.exist;
      expect(event?.args?.fromBeneficiary, "Incorrect fromBeneficiary").to.equal(owner.address);
      expect(event?.args?.toBeneficiary, "Incorrect toBeneficiary").to.equal(nominee.address);
      expect(event?.args?.registry, "Incorrect registry").to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId, "Incorrect tokenId").to.equal(42);
      expect(event?.args?.remark, "Incorrect remark").to.equal(ethers.utils.hexlify(remark));
    
      // Verify state changes
      expect(await titleEscrowMock.beneficiary(), "Beneficiary not updated").to.equal(nominee.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce not incremented"
      ).to.equal(1);
    });

    it("should succeed with max-length remark and emit BeneficiaryTransfer event", async () => {
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await titleEscrowMock.beneficiary(), "Initial beneficiary incorrect").to.equal(owner.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Initial nonce incorrect"
      ).to.equal(0);
    
      // Prepare transfer parameters with max-length remark (256 bytes)
      const longRemarkString = "a".repeat(256); // 256 ASCII chars = 256 bytes
      const remark = ethers.utils.toUtf8Bytes(longRemarkString);
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
    
      // Perform transfer
      const tx = await titleFlow
        .connect(deployer)
        .transferBeneficiary(nominee.address, remark, titleEscrowMock.address, actionData, signature, nonce);
      const receipt = await tx.wait();
    
      // Verify BeneficiaryTransfer event
      const event = receipt.events?.find((e) => e.event === "BeneficiaryTransfer");
      expect(event, "BeneficiaryTransfer event not emitted").to.exist;
      expect(event?.args?.fromBeneficiary, "Incorrect fromBeneficiary").to.equal(owner.address);
      expect(event?.args?.toBeneficiary, "Incorrect toBeneficiary").to.equal(nominee.address);
      expect(event?.args?.registry, "Incorrect registry").to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId, "Incorrect tokenId").to.equal(42);
      expect(event?.args?.remark, "Incorrect remark").to.equal(ethers.utils.hexlify(remark));
    
      // Verify state changes
      expect(await titleEscrowMock.beneficiary(), "Beneficiary not updated").to.equal(nominee.address);
      expect(
        await titleFlow.nonce(titleEscrowMock.address, owner.address),
        "Nonce not incremented"
      ).to.equal(1);
    });

    it("should prevent reentrancy attack via malicious title escrow (Test 10)", async () => {
      // Deploy malicious TitleEscrow contract
      const MaliciousTitleEscrow = await ethers.getContractFactory("MaliciousTitleEscrow");
      const maliciousTitleEscrow = await MaliciousTitleEscrow.deploy(titleFlow.address);
      await maliciousTitleEscrow.deployed();
    
      // Validate initial state
      const ATTORNEY_ADMIN_ROLE = await titleFlow.ATTORNEY_ADMIN_ROLE();
      expect(
        await titleFlow.hasRole(ATTORNEY_ADMIN_ROLE, deployer.address),
        "Deployer does not have ATTORNEY_ADMIN_ROLE"
      ).to.be.true;
      expect(await maliciousTitleEscrow.beneficiary(), "Initial beneficiary incorrect").to.equal(deployer.address);
      const initialNonce = await titleFlow.nonce(maliciousTitleEscrow.address, owner.address);
      expect(initialNonce, "Initial nonce incorrect").to.equal(0);
    
      // Prepare transfer parameters
      const remark = ethers.utils.toUtf8Bytes("Reentrancy test");
      const nonce = ethers.BigNumber.from(0);
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, maliciousTitleEscrow.address, nominee.address, ethers.constants.AddressZero, nonce, 1]
      );
    
      // Generate signature
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
    
      // Log initial state
      console.log(`Deployer address: ${deployer.address}`);
      console.log(`Malicious title escrow address: ${maliciousTitleEscrow.address}`);
      console.log(`Initial nonce: ${initialNonce.toString()}`);
      console.log(`Remark: ${ethers.utils.hexlify(remark)}`);
      console.log(`Signature: ${signature}`);
      console.log(`Action data: ${ethers.utils.hexlify(actionData)}`);
    
      // Attempt transfer with malicious title escrow
      try {
        const tx = await titleFlow
          .connect(deployer)
          .transferBeneficiary(nominee.address, remark, maliciousTitleEscrow.address, actionData, signature, nonce);
        const receipt = await tx.wait();
        console.log("Transaction succeeded unexpectedly. Receipt:", receipt);
        const finalNonce = await titleFlow.nonce(maliciousTitleEscrow.address, owner.address);
        console.log(`Final nonce: ${finalNonce.toString()}`);
        expect.fail("Expected transaction to revert with ReentrancyGuard: reentrant call");
      } catch (error: unknown) {
        if (error instanceof Error) {
          console.log("Revert reason:", error.message);
          expect(error.message).to.include("ReentrancyGuard: reentrant call");
        } else {
          console.log("Caught non-Error object:", error);
          expect.fail("Expected an Error object");
        }
      }
    
      // Verify state unchanged
      expect(await maliciousTitleEscrow.beneficiary(), "Beneficiary incorrectly changed").to.equal(deployer.address);
      expect(
        await titleFlow.nonce(maliciousTitleEscrow.address, deployer.address),
        "Nonce incorrectly incremented"
      ).to.equal(0);
    });

  });

  describe("transferOwners()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress; // Attorney (admin)
    let owner: SignerWithAddress;    // Owner who signs actions
    let nominee: SignerWithAddress;  // New beneficiary
    let newHolder: SignerWithAddress; // New holder
  
    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;
  
    beforeEach(async () => {
      [deployer, owner, nominee, newHolder] = await ethers.getSigners();
  
      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();
  
      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();
  
      await titleFlow.initialize(deployer.address, owner.address);
  
      // Set initial state in mock
      await titleEscrowMock.setState(
        owner.address,        // Initial beneficiary
        deployer.address,     // Initial holder
        zeroAddress,
        zeroAddress,
        zeroAddress,
        true,
        titleEscrowMock.address,
        42
      );
  
      // Verify initial state
      expect(await titleEscrowMock.beneficiary()).to.equal(owner.address);
      expect(await titleEscrowMock.holder()).to.equal(deployer.address);
    });
  
    it("should successfully transfer owners with valid signature and emit OwnersTransferred event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Owners transfer remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, newHolder.address, nonce, 3] // ActionType.OwnersTransfer = 3
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).transferOwners(
        nominee.address,
        newHolder.address,
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();
  
      // Verify event
      const event = receipt.events?.find((e) => e.event === "OwnersTransferred");
      expect(event).to.exist;
      expect(event?.args?.titleEscrow).to.equal(titleEscrowMock.address);
      expect(event?.args?.nominee).to.equal(nominee.address);
      expect(event?.args?.newHolder).to.equal(newHolder.address);
  
      // Verify nonce increment
      const newNonce = await titleFlow.nonce(titleEscrowMock.address, owner.address);
      expect(newNonce).to.equal(1);
  
      // Verify mock state
      expect(await titleEscrowMock.beneficiary()).to.equal(nominee.address);
      expect(await titleEscrowMock.holder()).to.equal(newHolder.address);
    });
  });


  describe("rejectTransferBeneficiary()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress;
    let owner: SignerWithAddress;
    let nominee: SignerWithAddress;
  
    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;
  
    beforeEach(async () => {
      [deployer, owner, nominee] = await ethers.getSigners();
  
      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();
  
      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();
  
      await titleFlow.initialize(deployer.address, owner.address);
  
      await titleEscrowMock.setState(
        owner.address,
        deployer.address,
        zeroAddress,
        zeroAddress,
        nominee.address,
        true,
        titleEscrowMock.address,
        42
      );
  
      expect(await titleEscrowMock.beneficiary()).to.equal(owner.address);
      expect(await titleEscrowMock.nominee()).to.equal(nominee.address);
    });
  
    it("should successfully reject beneficiary transfer with valid signature and emit RejectTransferBeneficiary event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Reject beneficiary remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, zeroAddress, nonce, 4]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).rejectTransferBeneficiary(
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();
  
      const event = receipt.events?.find((e) => e.event === "RejectTransferBeneficiary");
      expect(event).to.exist;
      expect(event?.args?.fromBeneficiary).to.equal(owner.address);
      expect(event?.args?.toBeneficiary).to.equal(nominee.address);
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));
  
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
      expect(await titleEscrowMock.nominee()).to.equal(zeroAddress);
    });
  });

  describe("rejectTransferHolder()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress; // Attorney (admin)
    let owner: SignerWithAddress;    // Owner who signs actions
    let newHolder: SignerWithAddress; // Proposed holder
  
    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;
  
    beforeEach(async () => {
      [deployer, owner, newHolder] = await ethers.getSigners();
  
      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();
  
      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();
  
      await titleFlow.initialize(deployer.address, owner.address);
  
      // Set initial state with a proposed holder
      await titleEscrowMock.setState(
        owner.address,        // Beneficiary
        deployer.address,     // Current holder
        zeroAddress,
        newHolder.address,    // Prev holder (proposed holder being rejected)
        zeroAddress,
        true,
        titleEscrowMock.address,
        42
      );
  
      expect(await titleEscrowMock.holder()).to.equal(deployer.address);
      expect(await titleEscrowMock.prevHolder()).to.equal(newHolder.address);
    });
  
    it("should successfully reject holder transfer with valid signature and emit RejectTransferHolder event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Reject holder remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, zeroAddress, nonce, 5]
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).rejectTransferHolder(
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();
  
      // Verify event
      const event = receipt.events?.find((e) => e.event === "RejectTransferHolder");
      expect(event).to.exist;
      expect(event?.args?.fromHolder).to.equal(deployer.address);
      expect(event?.args?.toHolder).to.equal(newHolder.address);
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));
  
      // Verify nonce increment
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
  
      // Verify mock state (prevHolder cleared)
      expect(await titleEscrowMock.prevHolder()).to.equal(zeroAddress);
    });
  });

  describe("rejectTransferOwners()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress; // Attorney (admin)
    let owner: SignerWithAddress;    // Owner who signs actions
    let nominee: SignerWithAddress;  // Proposed beneficiary
    let newHolder: SignerWithAddress; // Proposed holder
  
    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;
  
    beforeEach(async () => {
      [deployer, owner, nominee, newHolder] = await ethers.getSigners();
  
      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();
  
      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();
  
      await titleFlow.initialize(deployer.address, owner.address);
  
      // Set initial state with proposed nominee and holder
      await titleEscrowMock.setState(
        owner.address,        // Current beneficiary
        deployer.address,     // Current holder
        zeroAddress,
        newHolder.address,    // Prev holder (proposed holder)
        nominee.address,      // Nominee (proposed beneficiary)
        true,
        titleEscrowMock.address,
        42
      );
  
      expect(await titleEscrowMock.beneficiary()).to.equal(owner.address);
      expect(await titleEscrowMock.nominee()).to.equal(nominee.address);
      expect(await titleEscrowMock.holder()).to.equal(deployer.address);
      expect(await titleEscrowMock.prevHolder()).to.equal(newHolder.address);
    });
  
    it("should successfully reject owners transfer with valid signature and emit RejectTransferOwners event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Reject owners remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, zeroAddress, nonce, 6] // ActionType.RejectOwners = 6
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
      const tx = await titleFlow.connect(deployer).rejectTransferOwners(
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();
  
      // Verify event
      const event = receipt.events?.find((e) => e.event === "RejectTransferOwners");
      expect(event).to.exist;
      expect(event?.args?.fromBeneficiary).to.equal(owner.address);
      expect(event?.args?.toBeneficiary).to.equal(nominee.address);
      expect(event?.args?.fromHolder).to.equal(deployer.address);
      expect(event?.args?.toHolder).to.equal(zeroAddress);
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));
  
      // Verify nonce increment
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);
  
      // Verify mock state (nominee and prevHolder cleared)
      expect(await titleEscrowMock.nominee()).to.equal(zeroAddress);
      expect(await titleEscrowMock.prevHolder()).to.equal(zeroAddress);
    });
  });

  describe("returnToIssuer()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress; // Attorney (admin)
    let owner: SignerWithAddress;    // Owner who signs actions

    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;

    beforeEach(async () => {
      [deployer, owner] = await ethers.getSigners();

      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();

      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();

      await titleFlow.initialize(deployer.address, owner.address);

      // Set initial state
      await titleEscrowMock.setState(
        owner.address,        // Beneficiary
        deployer.address,     // Holder
        zeroAddress,
        zeroAddress,
        zeroAddress,
        true,                 // Active
        titleEscrowMock.address,
        42
      );

      expect(await titleEscrowMock.active()).to.be.true;
    });

    it("should successfully return to issuer with valid signature and emit ReturnToIssuer event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Return to issuer remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, zeroAddress, nonce, 7] // ActionType.ReturnToIssuer = 7
      );
      
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));

      const tx = await titleFlow.connect(deployer).returnToIssuer(
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();

      // Verify event
      const event = receipt.events?.find((e) => e.event === "ReturnToIssuer");
      expect(event).to.exist;
      expect(event?.args?.caller).to.equal(deployer.address);
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));

      // Verify nonce increment
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);

      // Verify mock state (active set to false)
      expect(await titleEscrowMock.active()).to.be.false;
    });
  });

  describe("shred()", () => {
    let titleFlow: TitleFlow;
    let titleEscrowMock: TitleEscrowMock;
    let deployer: SignerWithAddress; // Attorney (admin)
    let owner: SignerWithAddress;    // Owner who signs actions

    const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
    const zeroAddress = ethers.constants.AddressZero;

    beforeEach(async () => {
      [deployer, owner] = await ethers.getSigners();

      const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
      titleEscrowMock = await TitleEscrowMockFactory.deploy();
      await titleEscrowMock.deployed();

      const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
      titleFlow = await TitleFlowFactory.deploy();
      await titleFlow.deployed();

      await titleFlow.initialize(deployer.address, owner.address);

      // Set initial state
      await titleEscrowMock.setState(
        owner.address,        // Beneficiary
        deployer.address,     // Holder
        zeroAddress,
        zeroAddress,
        zeroAddress,
        true,                 // Active
        titleEscrowMock.address,
        42
      );

      expect(await titleEscrowMock.active()).to.be.true;
    });

    it("should successfully shred with valid signature and emit Shred event", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Shred remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, zeroAddress, zeroAddress, nonce, 8] // ActionType.Shred = 8
      );
      const messageHash = ethers.utils.keccak256(actionData);
      const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));

      const tx = await titleFlow.connect(deployer).shred(
        remark,
        titleEscrowMock.address,
        actionData,
        signature,
        nonce
      );
      const receipt = await tx.wait();

      // Verify event
      const event = receipt.events?.find((e) => e.event === "Shred");
      expect(event).to.exist;
      expect(event?.args?.registry).to.equal(titleEscrowMock.address);
      expect(event?.args?.tokenId).to.equal(42);
      expect(event?.args?.remark).to.equal(ethers.utils.hexlify(remark));

      // Verify nonce increment
      expect(await titleFlow.nonce(titleEscrowMock.address, owner.address)).to.equal(1);

      // Verify mock state (active set to false)
      expect(await titleEscrowMock.active()).to.be.false;
    });
  });

});


  
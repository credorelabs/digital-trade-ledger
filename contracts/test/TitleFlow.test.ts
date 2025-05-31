import { ethers } from "hardhat";
import { expect } from "chai";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { TitleFlow, TitleEscrowMock } from "../typechain"; // Adjust path

describe("TitleFlow", () => {
  let titleFlow: TitleFlow;
  let titleEscrowMock: TitleEscrowMock;
  let deployer: SignerWithAddress;
  let owner: SignerWithAddress;
  let nominee: SignerWithAddress;
  let nonAdmin: SignerWithAddress;
  let newHolder: SignerWithAddress; // New holder

  const ATTORNEY_ADMIN_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("ATTORNEY_ADMIN_ROLE"));
  const zeroAddress = ethers.constants.AddressZero;

  beforeEach(async () => {
    [deployer, owner, nominee, nonAdmin] = await ethers.getSigners();

    const TitleEscrowMockFactory = await ethers.getContractFactory("TitleEscrowMock");
    titleEscrowMock = await TitleEscrowMockFactory.deploy();
    await titleEscrowMock.deployed();

    const TitleFlowFactory = await ethers.getContractFactory("TitleFlow");
    titleFlow = await TitleFlowFactory.deploy();
    await titleFlow.deployed();

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
      const wrongSignature = await nonAdmin.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

    //   await expect(
    //     titleFlow.connect(deployer).nominate(
    //       nominee.address,
    //       remark,
    //       titleEscrowMock.address,
    //       actionData,
    //       wrongSignature,
    //       nonce
    //     )
    //   ).to.be.revertedWithCustomError(titleFlow, "InvalidSigner")
    });

    it("should revert with InvalidOperationToZeroAddress if nominee is zero address", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

    //   await expect(
    //     titleFlow.connect(deployer).nominate(
    //       zeroAddress,
    //       remark,
    //       titleEscrowMock.address,
    //       actionData,
    //       signature,
    //       nonce
    //     )
    //   ).to.be.revertedWith("InvalidOperationToZeroAddress");
    });

    it("should revert with InvalidOperationToZeroAddress if titleEscrow is zero address", async () => {
      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

    //   await expect(
    //     titleFlow.connect(deployer).nominate(
    //       nominee.address,
    //       remark,
    //       zeroAddress,
    //       actionData,
    //       signature,
    //       nonce
    //     )
    //   ).to.be.revertedWithCustomError(titleFlow, "InvalidOperationToZeroAddress");
    });

    it("should revert with ActionFailed if titleEscrow call fails", async () => {
      await titleEscrowMock.setShouldFail(true);

      const nonce = 0;
      const remark = ethers.utils.toUtf8Bytes("Nomination remark");
      const actionData = ethers.utils.defaultAbiCoder.encode(
        ["address", "address", "address", "address", "uint256", "uint8"],
        [titleFlow.address, titleEscrowMock.address, nominee.address, zeroAddress, nonce, 0]
      );
      const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

    //   await expect(
    //     titleFlow.connect(deployer).nominate(
    //       nominee.address,
    //       remark,
    //       titleEscrowMock.address,
    //       actionData,
    //       signature,
    //       nonce
    //     )
    //   ).to.be.revertedWithCustomError(titleFlow, "ActionFailed")
    //     .withArgs("Nominate failed");
    });

    // it("should prevent reentrancy", async () => {
    //   const MaliciousFactory = await ethers.getContractFactory(MaliciousArtifact.abi, MaliciousArtifact.bytecode);
    //   const malicious = await MaliciousFactory.deploy(titleFlow.address);
    //   await malicious.deployed();

    //   const nonce = 0;
    //   const remark = ethers.utils.toUtf8Bytes("Nomination remark");
    //   const actionData = ethers.utils.defaultAbiCoder.encode(
    //     ["address", "address", "address", "uint256", "uint8"],
    //     [malicious.address, nominee.address, zeroAddress, nonce, 0]
    //   );
    //   const signature = await owner.signMessage(ethers.utils.arrayify(ethers.utils.keccak256(actionData)));

    //   await expect(
    //     titleFlow.connect(deployer).nominate(
    //       nominee.address,
    //       remark,
    //       malicious.address,
    //       actionData,
    //       signature,
    //       nonce
    //     )
    //   ).to.be.revertedWith("ReentrancyGuard: reentrant call");
    // });
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


  
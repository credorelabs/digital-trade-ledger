import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers } from "hardhat";
import {
  SchemeManagement,
  SchemeManagement__factory,
} from "../typechain";

describe("SchemeManagement", function () {
    let schemeManagement: SchemeManagement;
    let admin: SignerWithAddress;
    let user1: SignerWithAddress;
    

    this.beforeEach(async () => {
        [admin, user1] = await ethers.getSigners();
        
        schemeManagement = await new SchemeManagement__factory(admin).deploy();
        await schemeManagement.grantRole(await schemeManagement.DEFAULT_ADMIN_ROLE(), admin.address);
        await schemeManagement.grantRole(await schemeManagement.SCHEME_ADMIN_ROLE(), admin.address);
    });

    describe("addScheme", function () {
        it("Should add a new scheme", async function () {
            const schemeId = ethers.utils.formatBytes32String("TEST_SCHEME_ID");
            const schemeName = ethers.utils.formatBytes32String("Test Scheme Name");
            const schemeDesc = ethers.utils.formatBytes32String("Test Scheme Description");
            const schemeRoot = ethers.utils.formatBytes32String("Test Merkle Root");
    
            // Call the addScheme method as the admin
            await schemeManagement.connect(admin).addScheme(schemeId, schemeName, schemeDesc, schemeRoot);
    
            // Check that the scheme was added correctly
            const [name, desc, hasRoot] = await schemeManagement.getScheme(schemeId);
            expect(name).to.equal(schemeName);
            expect(desc).to.equal(schemeDesc);
            expect(hasRoot).to.equal(true);
        });

        it("should revert if scheme does not exist", async () => {
            const schemeId = ethers.utils.formatBytes32String("nonexistent_scheme");
            const [name, desc, hasRoot] = await schemeManagement.getScheme(schemeId);
            expect(name).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000');
            expect(desc).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000');
            expect(hasRoot).to.equal(false);
            
        });
    
        it("should revert if non-admin tries to add a scheme", async function () {
            const schemeId = ethers.utils.formatBytes32String("TEST_SCHEME_ID");
            const schemeName = ethers.utils.formatBytes32String("Test Scheme Name");
            const schemeDesc = ethers.utils.formatBytes32String("Test Scheme Description");
            const schemeRoot = ethers.utils.formatBytes32String("Test Merkle Root");
        
            // Try to call the addScheme method as a non-admin
            await expect(schemeManagement.connect(user1).addScheme(schemeId, schemeName, schemeDesc, schemeRoot)).to.be.revertedWith("Must have DEFAULT_ADMIN_ROLE to add scheme");
        
            // Check that the scheme was not added
            const [name, desc, hasRoot] = await schemeManagement.getScheme(schemeId);
            expect(name).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
            expect(desc).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000");
            expect(hasRoot).to.equal(false);
        });
    
        it("should not add a new scheme if it already exists", async function () {
            const schemeId = ethers.utils.formatBytes32String("TEST_SCHEME_ID");
            const schemeName = ethers.utils.formatBytes32String("Test Scheme Name");
            const schemeDesc = ethers.utils.formatBytes32String("Test Scheme Description");
            const schemeRoot = ethers.utils.formatBytes32String("Test Merkle Root");
    
            // Call the addScheme method as the admin
            await schemeManagement.connect(admin).addScheme(schemeId, schemeName, schemeDesc, schemeRoot);
    
            // Attempt to add the same scheme again
            await expect(schemeManagement.connect(admin).addScheme(schemeId, schemeName, schemeDesc, schemeRoot)).to.be.revertedWith("Scheme ID already exists");
        });
    })
    

    describe("updateScheme", function () {
        const schemeId = ethers.utils.formatBytes32String("TEST_SCHEME");
        const schemeName = ethers.utils.formatBytes32String("Test Scheme");
        const schemeDescription = ethers.utils.formatBytes32String("A test scheme");
        const schemeMerkleRoot = ethers.utils.formatBytes32String("0x1234567890");
    
        beforeEach(async () => {
            await schemeManagement.connect(admin).addScheme(schemeId, schemeName, schemeDescription, schemeMerkleRoot);
        });
    
        it("should update the scheme", async function () {
          // Update the scheme
          await schemeManagement.connect(admin).updateScheme(schemeId, schemeName, schemeDescription, schemeMerkleRoot);
    
          // Check that the scheme has been updated
          const [name, description, hasMerkleRoot] = await schemeManagement.getScheme(schemeId);
          expect(name).to.equal(schemeName);
          expect(description).to.equal(schemeDescription);
          expect(hasMerkleRoot).to.be.true;
        });
    
        it("should only allow the admin to update the scheme", async function () {
          // Attempt to update the scheme as a non-admin
          const nonAdmin = (await ethers.getSigners())[1];
          await expect(
            schemeManagement.connect(nonAdmin).updateScheme(schemeId, schemeName, schemeDescription, schemeMerkleRoot)
          ).to.be.revertedWith("Must have DEFAULT_ADMIN_ROLE to update schemes");
    
          // Check that the scheme has not been updated
          const [name, description, hasMerkleRoot] = await schemeManagement.getScheme(schemeId);
          expect(name).to.equal(schemeName);
          expect(description).to.equal(schemeDescription);
          expect(hasMerkleRoot).to.be.true;
        });
    });
})
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { ethers } from "hardhat";
import { expect } from "chai";
import {
    DigitalAssetRegistry,
    DigitalAssetRegistry__factory,
}  from "../typechain";

describe("DigitalAssetRegistry", () => {
    let digitalAssetRegistry: DigitalAssetRegistry;
    let admin: SignerWithAddress;
    let operator: SignerWithAddress;
    let owner: SignerWithAddress;    
    let recipient: SignerWithAddress;

    before(async function () {
        [admin, operator, owner, recipient] = await ethers.getSigners();
        const uri = "https://credore.xyz/api/asset/{id}.json";
        digitalAssetRegistry = await new DigitalAssetRegistry__factory(admin).deploy(uri);
        
        await digitalAssetRegistry.grantRole(await digitalAssetRegistry.DEFAULT_ADMIN_ROLE(), admin.address);
        await digitalAssetRegistry.grantRole(await digitalAssetRegistry.TOKEN_ISSUER_ROLE(), admin.address);
        await digitalAssetRegistry.grantRole(await digitalAssetRegistry.TOKEN_ISSUER_ROLE(), operator.address);
    });

    it("Should allow admin to add asset", async function () {
        const id = ethers.utils.formatBytes32String("asset1");
        const merkleRoot = ethers.utils.formatBytes32String("root1");
        const assetType = ethers.utils.formatBytes32String("type1");
        const lei = ethers.utils.formatBytes32String("lei1");
        const leiVerificationDate = 1642492800; // January 18, 2022
        const originator = ethers.utils.formatBytes32String("originator1");
        const status = ethers.utils.formatBytes32String("issued");
        const count = 0

        await digitalAssetRegistry.addAsset(id, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count);
    
        const asset = await digitalAssetRegistry.getAsset(id);
        
        expect(asset.id).to.equal(id);
        expect(asset.nftId).to.equal(0);
        expect(asset.merkleRoot).to.equal(merkleRoot);
        expect(asset.assetType).to.equal(assetType);
        expect(asset.lei).to.equal(lei);
        expect(asset.leiVerificationDate).to.equal(leiVerificationDate);
        expect(asset.originator).to.equal(originator);
        expect(asset.status).to.equal(status);

        expect(await digitalAssetRegistry.assetExists(id)).to.equal(true);

        await expect(digitalAssetRegistry.addAsset(id, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count))
        .to.be.revertedWith("Asset already exists");
    });

    it("Should allow admin to update an asset", async () => {
        const nftId = 1;
        const id = ethers.utils.formatBytes32String("asset1");
        const merkleRoot = ethers.utils.formatBytes32String("root1");
        const assetType = ethers.utils.formatBytes32String("type1");
        const lei = ethers.utils.formatBytes32String("lei1");
        const leiVerificationDate = 1642492800; // January 18, 2022
        const originator = ethers.utils.formatBytes32String("originator1");
        const status = ethers.utils.formatBytes32String("funded");
        const count = 0
    
        await digitalAssetRegistry.updateAsset(id, nftId, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count);
    
        const asset = await digitalAssetRegistry.getAsset(id);
        
        expect(asset.id).to.equal(id);
        expect(asset.nftId).to.equal(nftId);
        expect(asset.merkleRoot).to.equal(merkleRoot);
        expect(asset.assetType).to.equal(assetType);
        expect(asset.lei).to.equal(lei);
        expect(asset.leiVerificationDate).to.equal(leiVerificationDate);
        expect(asset.originator).to.equal(originator);
        expect(asset.status).to.equal(status);
    
        await expect(digitalAssetRegistry.updateAsset(
          ethers.utils.id("nonExistingAsset"), nftId, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count
        )).to.be.revertedWith("Asset does not exist");
    });
});
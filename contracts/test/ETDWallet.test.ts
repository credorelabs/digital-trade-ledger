import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers } from "ethers";
import { ethers as hardhatEther } from "hardhat";
import {
    TitleEscrowTest,
    TitleEscrowTest__factory,
    ETDWallet__factory,
    ETDWallet,
    ETDWalletFactory,
    ETDWalletFactory__factory
} from "../typechain";

describe("ETDWallet - Electronic Trade Document Wallet", function () {
    let titleEscrowTT: TitleEscrowTest;    
    let etdWalletFactory: ETDWalletFactory;
    let deployer: SignerWithAddress;    
    
    let user1: SignerWithAddress;
    let user2: SignerWithAddress;
    let user3: SignerWithAddress;  
    
    let etdWalletUser1: ETDWallet;
    let etdWalletUser2: ETDWallet;
    let etdWalletUser3: ETDWallet;
    
    let futureETDWalletAddressUser1: string;
    let futureETDWalletAddressUser2: string;
    let futureETDWalletAddressUser3: string;

    const ZERO_ADDRESS: string = '0x0000000000000000000000000000000000000000';
    const implementation = '0x3B02fF1e626Ed7a8fd6eC5299e2C54e1421B626B';

    before(async () => {
        [deployer, user1, user2, user3] = await hardhatEther.getSigners();    
        etdWalletFactory = await new ETDWalletFactory__factory(deployer).deploy();
        titleEscrowTT = await new TitleEscrowTest__factory(deployer).deploy();
        
        futureETDWalletAddressUser1 = await etdWalletFactory.getAddress(user1.address)
        futureETDWalletAddressUser2 = await etdWalletFactory.getAddress(user2.address)
        await etdWalletFactory.create(user2.address);
        etdWalletUser2 = ETDWallet__factory.connect(futureETDWalletAddressUser2, deployer);

        futureETDWalletAddressUser3 = await etdWalletFactory.getAddress(user3.address)
        await etdWalletFactory.create(user3.address);
        etdWalletUser3 = ETDWallet__factory.connect(futureETDWalletAddressUser3, deployer);
    });
    it('should properly setup the ETDWallet Factory and provide the future address of the ETDWallet', async function () {        
        expect(implementation).to.equal(await etdWalletFactory.implementation());
        expect(futureETDWalletAddressUser1).to.equal(await etdWalletFactory.getAddress(user1.address));
    });

    it('should get the future address of the ETDWallet and match the address with the created wallet', async function () {                
        const actualETDWallet = await etdWalletFactory.create(user1.address);
        const rcpt = await actualETDWallet.wait();        
        expect(futureETDWalletAddressUser1).to.equal(rcpt.logs[0].address);
    });

    it('should properly configure all the smart contracts', async function () {
        etdWalletUser1 = ETDWallet__factory.connect(futureETDWalletAddressUser1, deployer);
        const owner = await etdWalletUser1.owner()
        expect(user1.address).to.equal(owner);
        
    });
    
    it('should transfer using attorney', async function () {        
        const newHolder = futureETDWalletAddressUser2;                
        const data = ethers.utils.formatBytes32String(`approved-transferHolder`);          
        const transferHolderHash = await etdWalletUser1.getApprovalHash(data);
        const signature = await user1.signMessage(ethers.utils.arrayify(transferHolderHash))
        const holderNonce = await etdWalletUser1.nonce(user1.address);
        
        await etdWalletUser1.transferHolder(titleEscrowTT.address, newHolder,data, signature, holderNonce);
        const holder = await titleEscrowTT.holder();
        
        expect(newHolder).to.equal(holder);
    });

    it('should nominate', async function () {
        const data = ethers.utils.formatBytes32String(`approved-nominate`);          
        const transferHolderHash = await etdWalletUser1.getApprovalHash(data);
        const signature = await user1.signMessage(ethers.utils.arrayify(transferHolderHash))
        let holderNonce = await etdWalletUser1.nonce(user1.address);

        const owner = await etdWalletUser1.owner()
        expect(user1.address).to.equal(owner);

        holderNonce = await etdWalletUser1.nonce(user1.address);
        await etdWalletUser1.nominate(futureETDWalletAddressUser2, titleEscrowTT.address, data, signature, holderNonce);
        const newNominee = await titleEscrowTT.nominee()
        expect(futureETDWalletAddressUser2).to.equal(newNominee);
    });

    it('should transfer beneficiary', async function () {
        const data = ethers.utils.formatBytes32String(`approved-transferBeneficiary`);          
        const transferHolderHash = await etdWalletUser1.getApprovalHash(data);
        const signature = await user1.signMessage(ethers.utils.arrayify(transferHolderHash))
        let holderNonce = await etdWalletUser1.nonce(user1.address);
        await etdWalletUser1.transferBeneficiary(titleEscrowTT.address, futureETDWalletAddressUser2, data, signature, holderNonce);
        expect(futureETDWalletAddressUser2).to.equal(await titleEscrowTT.beneficiary());
    });

    it('should let user 2 transfer ownership with user 3', async function () {
        let data = ethers.utils.formatBytes32String(`approved-nominate`);       
        let transferHolderHash = await etdWalletUser2.getApprovalHash(data);
        let signature = await user2.signMessage(ethers.utils.arrayify(transferHolderHash))
        let holderNonce = await etdWalletUser2.nonce(user2.address);
        
        await etdWalletUser2.nominate(etdWalletUser3.address, titleEscrowTT.address, data, signature, holderNonce);

        holderNonce = await etdWalletUser2.nonce(user2.address);
        data = ethers.utils.formatBytes32String(`approved-transferOwners`);       
        transferHolderHash = await etdWalletUser2.getApprovalHash(data);
        signature = await user2.signMessage(ethers.utils.arrayify(transferHolderHash))
        await etdWalletUser2.transferOwners(titleEscrowTT.address, etdWalletUser3.address, etdWalletUser3.address, data, signature, holderNonce)
        expect(etdWalletUser3.address).to.equal(await titleEscrowTT.holder());
        expect(etdWalletUser3.address).to.equal(await titleEscrowTT.beneficiary());

    });

    it('should let user 3 to surrender', async function () {
        let holderNonce = await etdWalletUser3.nonce(user3.address);
        let data = ethers.utils.formatBytes32String(`approved-surrender`);       
        let surrenderHash = await etdWalletUser3.getApprovalHash(data);
        let signature = await user3.signMessage(ethers.utils.arrayify(surrenderHash))
        await etdWalletUser3.surrender(titleEscrowTT.address, data, signature, holderNonce);
        expect(ZERO_ADDRESS).to.equal(await titleEscrowTT.nominee());        
    });

    it('should let user 3 to shred', async function () {
        let holderNonce = await etdWalletUser3.nonce(user3.address);
        let data = ethers.utils.formatBytes32String(`approved-shred`);       
        let surrenderHash = await etdWalletUser3.getApprovalHash(data);
        let signature = await user3.signMessage(ethers.utils.arrayify(surrenderHash))
        await etdWalletUser3.shred(titleEscrowTT.address, data, signature, holderNonce);
        expect(ZERO_ADDRESS).to.equal(await titleEscrowTT.nominee());
        expect(ZERO_ADDRESS).to.equal(await titleEscrowTT.holder());
        expect(ZERO_ADDRESS).to.equal(await titleEscrowTT.beneficiary());      
    });
});
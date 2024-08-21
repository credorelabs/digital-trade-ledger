import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import { BigNumber, ethers } from "ethers";
import { ethers as hardhatEther } from "hardhat";
import {
  Verifier,
  Verifier__factory,
  DigitalAssetRegistry,
  DigitalAssetRegistry__factory,
  MetaTx,
  MetaTx__factory,
  ZKVerifier__factory,
  ZKVerifier,
} from "../typechain";
// import { ZKPClient, EdDSA } from "circuits";
// import fs from "fs";
// import path from "path";
import { createHash } from "crypto";

export interface Proof {
    a: [bigint, bigint];
    b: [[bigint, bigint], [bigint, bigint]];
    c: [bigint, bigint];
}

describe("MetaTx", function () {
    let verifier: Verifier;
    let zkVerifier: ZKVerifier;
    let metaTx: MetaTx;
    let digitalAssetRegistry: DigitalAssetRegistry;
    let deployer: SignerWithAddress;    
    let user1: ethers.Wallet;
    let user2: ethers.Wallet;
    // let client: ZKPClient;
    // let eddsa: EdDSA;

    before(async () => {
        [deployer] = await hardhatEther.getSigners();    
        user1 = new ethers.Wallet(`0x2cf36dfbae17dca908d52b187dd57bef600c253421b3e69633b9c59178b44853`, hardhatEther.provider)
        user2 = new ethers.Wallet(`0xda9c8edea5f14b2819a76faf14f0585ff23638d27a6dc085024fe8eafd0afd79`, hardhatEther.provider)
        
        verifier = await new Verifier__factory(deployer).deploy();
        // eddsa = await new EdDSA(
        // "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        // ).init();
        
        zkVerifier = await new ZKVerifier__factory(deployer).deploy(verifier.address);
        metaTx = await new MetaTx__factory(deployer).deploy();
        const uri = "";
        digitalAssetRegistry = await new DigitalAssetRegistry__factory(deployer).deploy(uri);                
        
        // Setup
        await digitalAssetRegistry.grantRole(await digitalAssetRegistry.DEFAULT_ADMIN_ROLE(), deployer.address);
        await digitalAssetRegistry.grantRole(await digitalAssetRegistry.TOKEN_ISSUER_ROLE(), deployer.address);
        await digitalAssetRegistry.setMetaTxContractAddress(metaTx.address);
        await metaTx.setVerifier(verifier.address);
        await metaTx.setDigitalAssetRegistry(digitalAssetRegistry.address);

        // client = await new ZKPClient().init(
        //     fs.readFileSync(
        //         path.join(__dirname, "../../circuits/zk/circuits/main_js/main.wasm")
        //     ),
        //     fs.readFileSync(path.join(__dirname, "../../circuits/zk/zkeys/main.zkey"))
        // );
    })

    it('Should execute a method issueNFTUsingMetaTx in DigitalAssetRegistry with a valid proof', async function () {
        // console.log(`ethers.Wallet.createRandom().privateKey: ${ethers.Wallet.createRandom().privateKey}`)
        this.timeout(30000);

        const id = ethers.utils.formatBytes32String("asset1");
        const merkleRoot = '0x880b9fc5fff54df99b3e6843723b2309b5074f57ebe8ec41e27348ee75441f87';
        
        
        const assetType = ethers.utils.formatBytes32String("type1");
        const lei = ethers.utils.formatBytes32String("lei1");
        const leiVerificationDate = 1642492800; // January 18, 2022
        const originator = ethers.utils.formatBytes32String("originator1");
        const status = ethers.utils.formatBytes32String("issued");

        const target = digitalAssetRegistry.address;
        const nftOwner = await user1.getAddress();
        
        const hash = createHash("sha256").update(merkleRoot ).digest("hex");        
        
        let msg = BigNumber.from(`0x${hash}`);
        const sfv = BigNumber.from('21888242871839275222246405745257275088548364400416034343698204186575808495617')
        let count = 0;
        while(msg.gte(sfv)){
            msg = msg.sub(sfv)
            count++;
        }
        const data = digitalAssetRegistry.interface.encodeFunctionData(
            'issueNFTUsingMetaTx', 
            [id, nftOwner, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count]
        );
        
        const proofValue: any = {
            "a": ["3054131876831717064864763736106051148547972479609894092428002512823714144312", "19072931802538413231438453919783468667174576854139470196039826996904728182937"],
            "b": [["8055715869245873030771248529157560625905219828722184272793562787876269045598", "15471706208084238907493946600884810196381135841629136996963099847006615115419"], ["15077993575977827203221517356360808026694444572301006035864012124794282639268", "16017371686637924720844224481781839253628070561942664734152578717564741483061"]],
            "c": ["10306575046958680899546572735805753901478540687547386977915463668279262801996", "19495458836663242686472088357600845201167923978718869228862291224445297871387"]
          };
          
        const proof: Proof = {
            a: [BigInt(proofValue.a[0]), BigInt(proofValue.a[1])],
            b: [
                [BigInt(proofValue.b[0][0]), BigInt(proofValue.b[0][1])],
                [BigInt(proofValue.b[1][0]), BigInt(proofValue.b[1][1])]
            ],
            c: [BigInt(proofValue.c[0]), BigInt(proofValue.c[1])]
        };
        const scalarPubKey0 = BigNumber.from('21240519610593055392492042060669946222924144817081118368247193794739922230046')
        const scalarPubKey1 = BigNumber.from('4453285348027083154740111133239000238129114326358297327591877157074753938085')
        
        // Call the execute function on the MetaTx contract
        await metaTx.execute(
            target,
            data,
            [msg, scalarPubKey0.toBigInt(), scalarPubKey1.toBigInt()],
            proof
        );
        const asset = await metaTx.getAsset(id);        
        expect(asset.id).to.equal(id);
    });


    it("Should update an asset with a valid given zkp proof", async () => {
        this.timeout(30000)
        const id = ethers.utils.formatBytes32String("asset1");
        const merkleRoot = '0x880b9fc5fff54df99b3e6843723b2309b5074f57ebe8ec41e27348ee75441f87';
        const assetType = ethers.utils.formatBytes32String("type1");
        const lei = ethers.utils.formatBytes32String("lei1");
        const leiVerificationDate = 1642492800; // January 18, 2022
        const originator = ethers.utils.formatBytes32String("originator1");
        const status = ethers.utils.formatBytes32String("issued");        
        const target = digitalAssetRegistry.address;
        let asset = await metaTx.getAsset(id);
        const hash = createHash("sha256").update(merkleRoot ).digest("hex");
        
        let msg = BigNumber.from(`0x${hash}`);
        const nftId = asset.nftId;
        const sfv = BigNumber.from('21888242871839275222246405745257275088548364400416034343698204186575808495617')
        let count = 0;
        while(msg.gte(sfv)){
            msg = msg.sub(sfv)
            count++;
        }
        const data = digitalAssetRegistry.interface.encodeFunctionData(
            'updateAssetUsingMetaTx', 
            [id, nftId, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count]
        );
        

        const proofValue: any = {
            "a": ["21779580667854374600788200217823668421304580250888767403470158030250541705178","6688381779325615570064647559242987449285319264008981128988889859764975229556"],
            "b": [["14452590245456611890694674085449710443707639751926148659311245328736060699386","11628875547448356883574066276688265746953081859114449818803161553242488642747"],["4107784366206260381657911893965382914393184137672822569185913650784709050490","13256165851424473901787305248986275262412035442297162142693223213808076078159"]],
            "c": ["1984335392944566073194583238750942934449951344789980140813310964264876808252","10265670920648425447451164479828729275304703761934891987931544074802509760553"]
          };
          
        const proof: Proof = {
            a: [BigInt(proofValue.a[0]), BigInt(proofValue.a[1])],
            b: [
                [BigInt(proofValue.b[0][0]), BigInt(proofValue.b[0][1])],
                [BigInt(proofValue.b[1][0]), BigInt(proofValue.b[1][1])]
            ],
            c: [BigInt(proofValue.c[0]), BigInt(proofValue.c[1])]
        };
        const scalarPubKey0 = BigNumber.from('20455250687747779692724278275349802273242122589221126556611130777106535629320')
        const scalarPubKey1 = BigNumber.from('7215919187695675060644121133289697745160460136141448657598358404660625658127')
        
        // Call the execute function on the MetaTx contract
        await metaTx.execute(
            target,
            data,
            [msg, scalarPubKey0.toBigInt(), scalarPubKey1.toBigInt()],
            proof
        );
    
        asset = await metaTx.getAsset(id);        
        expect(asset.id).to.equal(id);
    
        asset = await metaTx.getAsset(id);
        
        expect(asset.id).to.equal(id);
        expect(asset.merkleRoot).to.equal(merkleRoot);
    }); 

   /* 
    it('Should perform a transaction tansmitting to blockchain', async function () {
        this.timeout(30000);

        const id = ethers.utils.formatBytes32String("asset1111111111");
        const merkleRoot = '0x7a6f6f7431726f6f7431726f6f7431726f6f7431000000000000000000000000';
        
        const assetType = ethers.utils.formatBytes32String("type1");
        const lei = ethers.utils.formatBytes32String("lei1");
        const leiVerificationDate = 1642492800; // January 18, 2022
        const originator = ethers.utils.formatBytes32String("originator1");
        const status = ethers.utils.formatBytes32String("issued");

        const target = '0xa1089Ae6327168190019386DECE49B92790A7374';
        const nftOwner = await user1.getAddress();
        const data = digitalAssetRegistry.interface.encodeFunctionData(
            'issueNFTUsingMetaTx', 
            [id, nftOwner, merkleRoot, assetType, lei, leiVerificationDate, originator, status]
        );

        const targetContractCallData = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["address", "bytes"], [target, data]));
        const msg = BigNumber.from(targetContractCallData);
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
            M: msg.toBigInt(),
            Ax: eddsa.scalarPubKey[0],
            Ay: eddsa.scalarPubKey[1],
            S: signature.S,
            R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
            R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        console.log(`proof: ${JSON.stringify(proof)}`)
        expect(
            await zkVerifier.verify(
                [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
                proof
            )
            ).to.eq(true);
        
    })
    */

    // it("Should be able to create a zkp and verify them", async function () {
        
    //     this.timeout(30000);
        
    //     const id = ethers.utils.formatBytes32String("asset1");
    //     const assetType = ethers.utils.formatBytes32String("type1");
    //     const lei = ethers.utils.formatBytes32String("lei1");
    //     const leiVerificationDate = 1642492800; // January 18, 2022
    //     const originator = ethers.utils.formatBytes32String("originator1");
    //     const status = ethers.utils.formatBytes32String("issued");

    //     //const target = digitalAssetRegistry.address;
    //     const target = '0x4b1f6ccbB2A12F49544a06dd0F7Ea724Cfeb2289'
    //     const nftOwner = await user1.getAddress();
    //     const merkleRoot = '0x880b9fc5fff54df99b3e6843723b2309b5074f57ebe8ec41e27348ee75441f87'

        
    //     // const msg = BigNumber.from(targetContractCallData);
    //     // console.log(`msg: ${msg}`)
    //     const hash = createHash("sha256").update(merkleRoot ).digest("hex");
    //     console.log(`hash: ${hash}`)
        
    //     //const msg = BigNumber.from(`0x${hash}`);
    //     let msg = BigNumber.from(`0x${hash}`);
    //     const sfv = BigNumber.from('21888242871839275222246405745257275088548364400416034343698204186575808495617')
    //     let count = 0;
    //     while(msg.gte(sfv)){
    //         msg = msg.sub(sfv)
    //         count++;
    //     }

    //     const data = digitalAssetRegistry.interface.encodeFunctionData(
    //         'issueNFTUsingMetaTx', 
    //         [id, nftOwner, merkleRoot, assetType, lei, leiVerificationDate, originator, status, count]
    //     );
    //     console.log(`msg: ${msg}`)
    //     console.log(`count: ${count}`)
    //     const eddsa1 = await new EdDSA(
    //         "0x2cf36dfbae17dca908d52b187dd57bef600c253421b3e69633b9c59178b44853"
    //         ).init();
    //     const signature = await eddsa1.sign(msg);
    //     const proof = await client.prove({
    //     M: msg.toBigInt(),
    //     Ax: eddsa1.scalarPubKey[0],
    //     Ay: eddsa1.scalarPubKey[1],
    //     S: signature.S,
    //     R8x: eddsa1.babyjub.F.toObject(signature.R8[0]),
    //     R8y: eddsa1.babyjub.F.toObject(signature.R8[1]),
    //     });

    //     expect(
    //     await zkVerifier.verify(
    //         [msg, eddsa1.scalarPubKey[0], eddsa1.scalarPubKey[1]],
    //         proof
    //     )
    //     ).to.eq(true);

    //     const signerKey = '0xfda56bef5f8bcffc230fd16fe0d200278777c6fbdf6a5d7070a49a2f0bd983c4';
    //     const rpc = 'https://klaytn-baobab-rpc.allthatnode.com:8551';
    //     //const rpc = 'https://erpc.apothem.network';
    //     const httpProvider = new ethers.providers.JsonRpcProvider(rpc);
    //     const signer = new ethers.Wallet(signerKey, httpProvider);
    //     const testNetMetaTx = MetaTx__factory.connect('0x7336F74DD4a68101AA77Cf128a1a313BB5145b97', signer);
    //     //const testNetMetaTx = MetaTx__factory.connect('0x4C0C2A5eAa82eCDaAA5Cfb77c99c8327d4603D92', signer);
    //     //const assetOld = await testNetMetaTx.getAsset(ethers.utils.formatBytes32String("asset7"));
        
    //     // Call the execute function on the MetaTx contract
    //     const result = await testNetMetaTx.execute(
    //         target,
    //         data,
    //         [msg, eddsa1.scalarPubKey[0], eddsa1.scalarPubKey[1]],
    //         proof
    //     );
    //     this.timeout(30000);
    //     console.log(`result: ${JSON.stringify(result)}`)

    //     const asset = await testNetMetaTx.getAsset(id);        
    //     //expect(asset.id).to.equal(id);
    //     console.log(`asset: ${JSON.stringify(asset)}`);
        

    // });

      

    // it("Should issue a token", async function () {
    //     const id = ethers.utils.formatBytes32String("asset1");
    //     const status = ethers.utils.formatBytes32String("tokenised");
    //     const nftOwner = await user1.getAddress();
    //     const data = ethers.utils.formatBytes32String(`Tokenisation Request`);
    //     const target = digitalAssetRegistry.address;

    //     const hashForTransfer = await metaTx.getIssueNFTHash(id, nftOwner, status, data, deployer.address);
    //     const sigForTransfer = await user1.signMessage(ethers.utils.arrayify(hashForTransfer));        

    //     const methodData = digitalAssetRegistry.interface.encodeFunctionData(
    //         'issueNFT', 
    //         [id, nftOwner, status]
    //     );
        
    //     await metaTx.executeIssueNFT(target, id, status, nftOwner, data, deployer.address, sigForTransfer, methodData);
    //     const asset = await metaTx.getAsset(id);
    //     expect(await digitalAssetRegistry.balanceOf(nftOwner, asset.nftId.toNumber())).to.equal(1);
    // });

    // it("Should approve and transfer a token", async function () {
    //     const id = ethers.utils.formatBytes32String("asset1");        
    //     const asset = await metaTx.getAsset(id);
        
        
    //     // Assemble transfer data
    //     const from = await user1.getAddress();
    //     const to = await user2.getAddress();
    //     const data = ethers.utils.formatBytes32String(`Transferring asset ownership`);
    //     const transferAmount = 1;
    //     const target = digitalAssetRegistry.address;

    //    const hashForTransfer = await metaTx.getTransferNFTHash(from, to, asset.nftId.toString(), transferAmount, data, deployer.address);
    //    const sigForTransfer = await user1.signMessage(ethers.utils.arrayify(hashForTransfer));

    //    const methodData = digitalAssetRegistry.interface.encodeFunctionData(
    //         'transferToken', 
    //         [from, to, asset.nftId.toString(), transferAmount, data, deployer.address]
    //     );
        
    //     // Verify the token balances before transfer
    //     expect(await digitalAssetRegistry.balanceOf(from, asset.nftId.toNumber())).to.equal(transferAmount);

    //     await metaTx.executeTransferNFT(target, from, to, asset.nftId.toString(), transferAmount, data, deployer.address, sigForTransfer, methodData);

    //     // Verify the token balances
    //     expect(await digitalAssetRegistry.balanceOf(from, asset.nftId.toNumber())).to.equal(0);
    //     expect(await digitalAssetRegistry.balanceOf(to, asset.nftId.toNumber())).to.equal(transferAmount);
                  
    // });

    // it("Should approve and transfer a token just print", async function () {
        // const id = ethers.utils.formatBytes32String("INV66612");        
        // const nftOwner = await user1.getAddress();
        // const data = '0x'
        // const target = '0xc7d8E9600a5D2FB4403c65cd95F0C0aE774d326F'//digitalAssetRegistry.address;
        // const trustedForwarder = '0x49c11F25f101CE6B0f5bBE12d316AB9Ecc1bFbec'
        // const status = ethers.utils.formatBytes32String("tokenised");
        // const methodData = digitalAssetRegistry.interface.encodeFunctionData(
        //     'issueNFT', 
        //     [id, nftOwner, status]
        // );
        // const hashForTransfer = await metaTx.getIssueNFTHash(
        //     id, 
        //     nftOwner, 
        //     status,
        //     data, 
        //     trustedForwarder);
        // const sigForTransfer = await user1.signMessage(ethers.utils.arrayify(hashForTransfer));        

        // console.log(`hashForTransfer: ${hashForTransfer}`)
        // console.log(`dsaAddress: ${target}`)
        // console.log(`trustedForwarder: ${trustedForwarder}`)
        // console.log(`id: ${id}`)
        // console.log(`nftRecipient: ${nftOwner}`)
        // console.log(`data: ${data}`)
        // console.log(`sigForTransfer: ${sigForTransfer}`)
        // console.log(`methodData: ${methodData}`)
        //const asset = await metaTx.getAsset(id);
        
        
        // Assemble transfer data
    //     const from = await user1.getAddress();
    //     const to = await user2.getAddress();
    //     const data = ethers.utils.formatBytes32String(`Transferring asset ownership`);
    //     const transferAmount = 1;
    //     const target = digitalAssetRegistry.address;

    //     const trustedForwarder = '0x49c11F25f101CE6B0f5bBE12d316AB9Ecc1bFbec'
    //     const hashForTransfer = await metaTx.getTransferNFTHash(from, to, asset.nftId.toString(), transferAmount, data, trustedForwarder);
    //     const sigForTransfer = await user1.signMessage(ethers.utils.arrayify(hashForTransfer));

    //    const methodData = digitalAssetRegistry.interface.encodeFunctionData(
    //         'transferToken', 
    //         [from, to, asset.nftId.toString(), transferAmount, data, deployer.address]
    //     );

    //     console.log(`target: ${target}`)
    //     console.log(`id: ${id}`)
    //     console.log(`from: ${from}`)
    //     console.log(`to: ${to}`)
    //     console.log(`transferAmount: ${transferAmount}`)
    //     console.log(`data: ${data}`)
    //     console.log(`deployer: ${deployer.address}`)
    //     console.log(`asset.nftId.toString(): ${asset.nftId.toString()}`)
    //     console.log(`sigForTransfer: ${sigForTransfer}`)
    //     console.log(`methodData: ${methodData}`)
        
        // Verify the token balances before transfer
        // expect(await digitalAssetRegistry.balanceOf(from, asset.nftId.toNumber())).to.equal(transferAmount);

        // await metaTx.executeTransferNFT(target, from, to, asset.nftId.toString(), transferAmount, data, deployer.address, sigForTransfer, methodData);

        // // Verify the token balances
        // expect(await digitalAssetRegistry.balanceOf(from, asset.nftId.toNumber())).to.equal(0);
        // expect(await digitalAssetRegistry.balanceOf(to, asset.nftId.toNumber())).to.equal(transferAmount);
                  
    // });

})
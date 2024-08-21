import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import { ethers } from "hardhat";
import {
  Verifier,
  Verifier__factory,
  ZKVerifier,
  ZKVerifier__factory,
} from "../typechain";
import { ZKPClient, EdDSA } from "circuits";
import { BigNumber } from "ethers";
import fs from "fs";
import path from "path";

describe("ZKVerifier", function () {
    let verifier: Verifier;
    let zkVerifier: ZKVerifier;
    let deployer: SignerWithAddress;
    let client: ZKPClient;
    let eddsa: EdDSA;

    before(async () => {
        [deployer] = await ethers.getSigners();
        verifier = await new Verifier__factory(deployer).deploy();
        eddsa = await new EdDSA(
        "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        ).init();
        zkVerifier = await new ZKVerifier__factory(deployer).deploy(verifier.address);
        client = await new ZKPClient().init(
            fs.readFileSync(
                path.join(__dirname, "../../circuits/zk/circuits/main_js/main.wasm")
            ),
            fs.readFileSync(path.join(__dirname, "../../circuits/zk/zkeys/main.zkey"))
        );
    });

    it("Should be able to create a zkp and verify them", async function () {
        const msg = BigNumber.from("0xabcd");
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        expect(
        await zkVerifier.verify(
            [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )
        ).to.eq(true);
    });

    it("Should be able to create a zkp and not be able to verify them", async function () {
        const msg = BigNumber.from("0xabcd");
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        const msgModified = BigNumber.from("0xabcde");
        expect(
        await zkVerifier.verify(
            [msgModified, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )
        ).to.eq(false);
    });

    it("Should be able to record a zkp public input and be able to verify them", async function () {
        const id = ethers.utils.formatBytes32String("asset4");
        const msg = BigNumber.from("0xabcd");
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        await zkVerifier.record(
            id,
            [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )

        const publicInput0 = await zkVerifier.records(id,0)
        const publicInput1 = await zkVerifier.records(id,1)
        const publicInput2 = await zkVerifier.records(id,2)
        
        expect(
            await zkVerifier.verify(
                [publicInput0, publicInput1, publicInput2],
                proof
            )
        ).to.eq(true);
    });

    it("Should not record a zkp with a wrong public input", async function () {
        const id = ethers.utils.formatBytes32String("asset5");
        const msg = BigNumber.from("0xabcd");
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        const msgModified = BigNumber.from("0xabcde");

        await expect(zkVerifier.record(
            id,
            [msgModified, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )).to.be.revertedWith("SNARK signature verification failed");
    });

    it("Should verify the ZKP signature by asset id", async function () {
        const id = ethers.utils.formatBytes32String("asset6");
        const msg = BigNumber.from("0xabcd");
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        await zkVerifier.record(
            id,
            [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )

        expect(
            await zkVerifier.verifyById("asset6")
        ).to.eq(true);
    });
});
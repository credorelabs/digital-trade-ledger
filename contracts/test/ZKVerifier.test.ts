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
    let recorder: SignerWithAddress;
    let recorderWithoutRoleAccess: SignerWithAddress;
    let client: ZKPClient;
    let eddsa: EdDSA;

    const content = "Specific content to be signed";
    let contentHash: BigNumber;
    const snarkScalarField = BigNumber.from(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    );

    before(async () => {
        [deployer, recorder, recorderWithoutRoleAccess] = await ethers.getSigners();

        verifier = await new Verifier__factory(deployer).deploy();
        eddsa = await new EdDSA(
        "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        ).init();
        zkVerifier = await new ZKVerifier__factory(deployer).deploy(verifier.address);
        await zkVerifier.deployed();

        // Grant RECORDER_ROLE to recorder
        await zkVerifier.grantRecorderRole(recorder.address);

        client = await new ZKPClient().init(
            fs.readFileSync(
                path.join(__dirname, "../../circuits/zk/circuits/main_js/main.wasm")
            ),
            fs.readFileSync(path.join(__dirname, "../../circuits/zk/zkeys/main.zkey"))
        );

        // Compute content hash and reduce modulo snark_scalar_field
        contentHash = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);

    });

    it("Should hash content correctly", async function () {
        const rawHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content));
        const expectedHash = BigNumber.from(rawHash).mod(snarkScalarField);
        expect(contentHash).to.equal(expectedHash);
    });

    it("Should be able to create a zkp and verify them", async function () {
        // Sign the content hash
        const signature = await eddsa.sign(contentHash);
        const proof = await client.prove({
        M: contentHash.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        expect(
        await zkVerifier.verify(
            [contentHash, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )
        ).to.eq(true);
    });

    it("Should create a ZKP but fail verification with wrong content hash", async function () {
        // Sign the correct content hash
        const signature = await eddsa.sign(contentHash);
    
        // Generate proof
        const proof = await client.prove({
          M: contentHash.toBigInt(),
          Ax: eddsa.scalarPubKey[0],
          Ay: eddsa.scalarPubKey[1],
          S: signature.S,
          R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
          R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });
    
        // Use wrong content hash
        const wrongContent = "Wrong content";
        const wrongHash = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(wrongContent))
        ).mod(snarkScalarField);
    
        // Verify with wrong hash
        const result = await zkVerifier.verify(
          [wrongHash, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
          proof
        );
        expect(result).to.eq(false);
    });

    it("Should be able to record a zkp public input and be able to verify them", async function () {
        const id = ethers.utils.formatBytes32String("asset4");
        const content = "Should be able to record a zkp public input and be able to verify them";
        const msg = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);
        
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
        const content = "Should be able to record a zkp public input and be able to verify them";
        const msg = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
        M: msg.toBigInt(),
        Ax: eddsa.scalarPubKey[0],
        Ay: eddsa.scalarPubKey[1],
        S: signature.S,
        R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
        R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });

        const modifiedContent = "Wrong Content: Should be able to record a zkp public input and be able to verify them";
        const msgModified = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(modifiedContent))
        ).mod(snarkScalarField);

        await expect(zkVerifier.record(
            id,
            [msgModified, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
            proof
        )).to.be.revertedWith("SNARK signature verification failed");
    });

    it("Should verify the ZKP signature by asset id", async function () {
        const id = ethers.utils.formatBytes32String("asset6");
        const content = "Should verify the ZKP signature by asset id";
        const msg = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);

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

    it("Should fail to record without RECORD_ROLE", async function () {
        const id = ethers.utils.formatBytes32String("asset7");

        // Sign the content hash
        const signature = await eddsa.sign(contentHash);
        const roleHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("RECORD_ROLE"));
        // Verify nonRecorder lacks RECORD_ROLE
        expect(
            await zkVerifier.hasRole(
            roleHash,
            recorderWithoutRoleAccess.address
            )
        ).to.eq(false);
        // Generate proof
        const proof = await client.prove({
            M: contentHash.toBigInt(),
            Ax: eddsa.scalarPubKey[0],
            Ay: eddsa.scalarPubKey[1],
            S: signature.S,
            R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
            R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });
        
        await expect(
            zkVerifier.connect(recorderWithoutRoleAccess).record(
              id,
              [contentHash, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]],
              proof
            )
        ).to.be.revertedWith(`AccessControl: account ${recorderWithoutRoleAccess.address.toLowerCase()} is missing role ${roleHash}`)
    });

    it("Should grant and revoke RECORD_ROLE", async function () {
        const newRecorder = (await ethers.getSigners())[3];
    
        // Grant RECORD_ROLE
        await zkVerifier.grantRecorderRole(newRecorder.address);
        expect(await zkVerifier.hasRole(ethers.utils.keccak256(ethers.utils.toUtf8Bytes("RECORD_ROLE")), newRecorder.address)).to.eq(true);
    
        // Revoke RECORD_ROLE
        await zkVerifier.revokeRecorderRole(newRecorder.address);
        expect(await zkVerifier.hasRole(ethers.utils.keccak256(ethers.utils.toUtf8Bytes("RECORD_ROLE")), newRecorder.address)).to.eq(false);
    });
    
    it("Should fail to verifyById with non-existent ID", async function () {
        const result = await zkVerifier.verifyById("nonexistent");
        expect(result).to.eq(false);
    });
});
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

    it("should revert for zero publicSignals[1]", async function () {
        const id = ethers.utils.formatBytes32String("asset4");
        const content = "Test zero public signal";
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
      
        await expect(
          zkVerifier.record(id, [msg, 0, eddsa.scalarPubKey[1]], proof)
        ).to.be.revertedWith("Invalid public signal");
    });

    it("should revert for zero proof.a[0]", async function () {
        const id = ethers.utils.formatBytes32String("asset4");
        const content = "Test zero proof a[0]";
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
        
        const invalidProof = {
            a: [0, proof.a[1]], // Set proof.a[0] to 0
            b: proof.b,
            c: proof.c,
        };
        
      
        await expect(
          zkVerifier.record(id, [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]], {
            a: [0, proof.a[1]], // Set proof.a[0] to 0
            b: proof.b,
            c: proof.c,
          })
        ).to.be.revertedWith("Invalid proof");
    });
    it("should revert for existing _id", async function () {
        const id = ethers.utils.formatBytes32String("asset5");
        const content = "Test existing ID";
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
      
        // Record first proof successfully
        await zkVerifier.record(id, [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]], proof);
      
        // Attempt to record again with same ID
        await expect(
          zkVerifier.record(id, [msg, eddsa.scalarPubKey[0], eddsa.scalarPubKey[1]], proof)
        ).to.be.revertedWith("Record already exists");
    });

    it("should correctly update records and proofs after recording", async function () {
        // Use a unique ID to avoid conflicts
        const id = ethers.utils.formatBytes32String("test12_asset4");
        const content = "Test record and proof updates";
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
      
        // Type-safe validSignals
        const validSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]),
          BigNumber.from(eddsa.scalarPubKey[1]),
        ];
      
        await zkVerifier.record(id, validSignals, proof);
      
        // Debug stored records
        const storedSignals = [
          await zkVerifier.records(id, 0),
          await zkVerifier.records(id, 1),
          await zkVerifier.records(id, 2),
        ];        
      
        // Verify records mapping
        expect(storedSignals[0]).to.equal(validSignals[0]);
        expect(storedSignals[1]).to.equal(validSignals[1]);
        expect(storedSignals[2]).to.equal(validSignals[2]);
      
        // Verify proofs mapping
        const storedProof = await zkVerifier.getProof(id);
        expect(storedProof.a[0]).to.equal(proof.a[0]);
        expect(storedProof.a[1]).to.equal(proof.a[1]);
        expect(storedProof.b[0][0]).to.equal(proof.b[0][0]);
        expect(storedProof.b[0][1]).to.equal(proof.b[0][1]);
        expect(storedProof.b[1][0]).to.equal(proof.b[1][0]);
        expect(storedProof.b[1][1]).to.equal(proof.b[1][1]);
        expect(storedProof.c[0]).to.equal(proof.c[0]);
        expect(storedProof.c[1]).to.equal(proof.c[1]);
    });

    it("should emit correct RecordAdded event", async function () {
        const id = ethers.utils.formatBytes32String("test13_asset5");
        const content = "Test RecordAdded event emission";
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
      
        const validSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]),
          BigNumber.from(eddsa.scalarPubKey[1]),
        ];
      
        const tx = await zkVerifier.record(id, validSignals, proof);
        const receipt = await tx.wait();
      
        const event = receipt.events?.find(e => e.event === "RecordAdded");
        expect(event, "RecordAdded event not emitted").to.exist;
        expect(event?.args?.id).to.equal(id);
    });

    it("should succeed with large publicSignals values", async function () {
        const id = ethers.utils.formatBytes32String("test14_asset6");
        const scalarField = BigNumber.from(snarkScalarField);
      
        // Use a large message and valid EdDSA public key
        const content = "Test large public signals";
        const msg = BigNumber.from(
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(scalarField).sub(1); // Large but valid message
      
        // Use valid EdDSA public key components
        const largeSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]), // Valid Ax
          BigNumber.from(eddsa.scalarPubKey[1]), // Valid Ay
        ];
      
        // Generate signature and proof with matching inputs
        const signature = await eddsa.sign(msg);
        const proof = await client.prove({
          M: msg.toBigInt(),
          Ax: eddsa.scalarPubKey[0],
          Ay: eddsa.scalarPubKey[1],
          S: signature.S,
          R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
          R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });
      
        // Record with large publicSignals
        const tx = await zkVerifier.record(id, largeSignals, proof);
        const receipt = await tx.wait();
      
        // Verify RecordAdded event
        const event = receipt.events?.find(e => e.event === "RecordAdded");
        expect(event, "RecordAdded event not emitted").to.exist;
        expect(event?.args?.id).to.equal(id);
      
        // Verify records mapping
        expect(await zkVerifier.records(id, 0)).to.equal(largeSignals[0]);
        expect(await zkVerifier.records(id, 1)).to.equal(largeSignals[1]);
        expect(await zkVerifier.records(id, 2)).to.equal(largeSignals[2]);
    });

    it("should succeed with zero _id", async function () {
        const id = ethers.constants.HashZero; // Zero bytes32: 0x0000000000000000000000000000000000000000000000000000000000000000
        const content = "Test zero ID";
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
      
        const validSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]),
          BigNumber.from(eddsa.scalarPubKey[1]),
        ];
      
        // Record with zero ID
        const tx = await zkVerifier.record(id, validSignals, proof);
        const receipt = await tx.wait();
      
        // Verify RecordAdded event
        const event = receipt.events?.find(e => e.event === "RecordAdded");
        expect(event, "RecordAdded event not emitted").to.exist;
        expect(event?.args?.id).to.equal(id);
      
        // Verify records mapping
        expect(await zkVerifier.records(id, 0)).to.equal(validSignals[0]);
        expect(await zkVerifier.records(id, 1)).to.equal(validSignals[1]);
        expect(await zkVerifier.records(id, 2)).to.equal(validSignals[2]);
      
        // Verify proofs mapping
        const storedProof = await zkVerifier.getProof(id);
        expect(storedProof.a[0]).to.equal(proof.a[0]);
        expect(storedProof.a[1]).to.equal(proof.a[1]);
        expect(storedProof.b[0][0]).to.equal(proof.b[0][0]);
        expect(storedProof.b[0][1]).to.equal(proof.b[0][1]);
        expect(storedProof.b[1][0]).to.equal(proof.b[1][0]);
        expect(storedProof.b[1][1]).to.equal(proof.b[1][1]);
        expect(storedProof.c[0]).to.equal(proof.c[0]);
        expect(storedProof.c[1]).to.equal(proof.c[1]);
    });

    it("should correctly convert long string _id via stringToBytes32", async function () {
        // 32-character string ID
        const longIdString = "test25_long_id_1234567890123456"; // Exactly 32 chars
        const expectedId = ethers.utils.formatBytes32String(longIdString); // Convert to bytes32
        const content = "Test long string ID";
        const msg = BigNumber.from(
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);
      
        // Validate inputs
        expect(snarkScalarField, "snarkScalarField is undefined").to.not.be.undefined;
        expect(msg, "msg is undefined").to.not.be.undefined;
        expect(eddsa.scalarPubKey[0], "eddsa.scalarPubKey[0] is undefined").to.not.be.undefined;
        expect(eddsa.scalarPubKey[1], "eddsa.scalarPubKey[1] is undefined").to.not.be.undefined;
      
        const signature = await eddsa.sign(msg);
        expect(signature, "signature is undefined").to.not.be.undefined;
        expect(signature.S, "signature.S is undefined").to.not.be.undefined;
        expect(signature.R8, "signature.R8 is undefined").to.not.be.undefined;
      
        const proof = await client.prove({
          M: msg.toBigInt(),
          Ax: eddsa.scalarPubKey[0],
          Ay: eddsa.scalarPubKey[1],
          S: signature.S,
          R8x: eddsa.babyjub.F.toObject(signature.R8[0]),
          R8y: eddsa.babyjub.F.toObject(signature.R8[1]),
        });
        expect(proof, "proof is undefined").to.not.be.undefined;
      
        const validSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]),
          BigNumber.from(eddsa.scalarPubKey[1]),
        ];
      
        // Verify stringToBytes32 conversion
        const convertedId = await zkVerifier.stringToBytes32(longIdString);
        expect(convertedId, "convertedId does not match expected").to.equal(expectedId);
      
        // Record with long string ID (converted internally by verifyById)
        const id = convertedId; // Use converted bytes32 ID
        const tx = await zkVerifier.record(id, validSignals, proof);
        const receipt = await tx.wait();
      
        // Verify RecordAdded event
        const event = receipt.events?.find(e => e.event === "RecordAdded");
        expect(event, "RecordAdded event not emitted").to.exist;
        expect(event?.args?.id).to.equal(id);
      
        // Verify records mapping
        expect(await zkVerifier.records(id, 0)).to.equal(validSignals[0]);
        expect(await zkVerifier.records(id, 1)).to.equal(validSignals[1]);
        expect(await zkVerifier.records(id, 2)).to.equal(validSignals[2]);
    });

    it("should return correct numRecords after multiple record calls", async function () {
        const ids = [
          ethers.utils.formatBytes32String("test26_asset10"),
          ethers.utils.formatBytes32String("test26_asset11"),
          ethers.utils.formatBytes32String("test26_asset12"),
        ];
        const content = "Test multiple record calls";
        const recordsCount = ids.length;
      
        // Check existing numRecords before adding new records
        const initialNumRecords = await zkVerifier.totalRecords();
        expect(initialNumRecords, "initialNumRecords is undefined").to.not.be.undefined;
      
        // Validate snarkScalarField
        expect(snarkScalarField, "snarkScalarField is undefined").to.not.be.undefined;
      
        for (let i = 0; i < recordsCount; i++) {
          const contentWithIndex = `${content}_${i}`;
          const msg = BigNumber.from(
            ethers.utils.keccak256(ethers.utils.toUtf8Bytes(contentWithIndex))
          ).mod(snarkScalarField);
      
          // Validate inputs
          expect(msg, `msg is undefined for index ${i}`).to.not.be.undefined;
          expect(eddsa.scalarPubKey[0], `eddsa.scalarPubKey[0] is undefined for index ${i}`).to.not.be.undefined;
          expect(eddsa.scalarPubKey[1], `eddsa.scalarPubKey[1] is undefined for index ${i}`).to.not.be.undefined;
      
          const signature = await eddsa.sign(msg);
          expect(signature, `signature is undefined for index ${i}`).to.not.be.undefined;
          expect(signature.S, `signature.S is undefined for index ${i}`).to.not.be.undefined;
          expect(signature.R8, `signature.R8 is undefined for index ${i}`).to.not.be.undefined;
          expect(signature.R8[0], `signature.R8[0] is undefined for index ${i}`).to.not.be.undefined;
          expect(signature.R8[1], `signature.R8[1] is undefined for index ${i}`).to.not.be.undefined;
      
          expect(eddsa.babyjub.F, `eddsa.babyjub.F is undefined for index ${i}`).to.not.be.undefined;
          const r8x = eddsa.babyjub.F.toObject(signature.R8[0]);
          const r8y = eddsa.babyjub.F.toObject(signature.R8[1]);
          expect(r8x, `r8x is undefined for index ${i}`).to.not.be.undefined;
          expect(r8y, `r8y is undefined for index ${i}`).to.not.be.undefined;
      
          const proof = await client.prove({
            M: msg.toBigInt(),
            Ax: eddsa.scalarPubKey[0],
            Ay: eddsa.scalarPubKey[1],
            S: signature.S,
            R8x: r8x,
            R8y: r8y,
          });
          expect(proof, `proof is undefined for index ${i}`).to.not.be.undefined;
      
          const validSignals: [BigNumber, BigNumber, BigNumber] = [
            msg,
            BigNumber.from(eddsa.scalarPubKey[0]),
            BigNumber.from(eddsa.scalarPubKey[1]),
          ];
      
          // Record proof
          const tx = await zkVerifier.record(ids[i], validSignals, proof);
          await tx.wait();
      
          // Verify numRecords after each record
          const currentNumRecords = await zkVerifier.totalRecords();
          expect(currentNumRecords, `numRecords is undefined for index ${i}`).to.not.be.undefined;
          expect(currentNumRecords).to.equal(initialNumRecords.add(i + 1));
        }
      
        // Final verification of numRecords
        const finalNumRecords = await zkVerifier.totalRecords();
        expect(finalNumRecords).to.equal(initialNumRecords.add(recordsCount));
    });
    
    it("should convert max-length string to bytes32 correctly (Test 30)", async function () {
        // 31-character string (31 bytes in ASCII, max for formatBytes32String)
        const maxLengthString = "abcdefghijklmnopqrstuvwxyz01234"; // 31 chars
        const expectedBytes32 = ethers.utils.formatBytes32String(maxLengthString); // Reference conversion
      
        // Verify string length
        expect(maxLengthString.length, "Input string length is not 31").to.equal(31);
      
        // Verify stringToBytes32 conversion
        const convertedBytes32 = await zkVerifier.stringToBytes32(maxLengthString);
        expect(convertedBytes32, "convertedBytes32 does not match expected").to.equal(expectedBytes32);
    });

    it("should grant RECORDER_ROLE to new account successfully (Test 33)", async function () {
        // Setup accounts (use a fresh account for newRecorder)
        const [admin, , , freshRecorder] = await ethers.getSigners(); // Use 4th signer to avoid prior role assignments
        const RECORDER_ROLE = await zkVerifier.RECORDER_ROLE();
        const DEFAULT_ADMIN_ROLE = await zkVerifier.DEFAULT_ADMIN_ROLE();      
      
        // Validate admin role
        expect(
          await zkVerifier.hasRole(DEFAULT_ADMIN_ROLE, admin.address),
          "Admin does not have DEFAULT_ADMIN_ROLE"
        ).to.be.true;
      
        // Verify freshRecorder initially lacks RECORDER_ROLE
        const hasRecorderRole = await zkVerifier.hasRole(RECORDER_ROLE, freshRecorder.address);
        expect(hasRecorderRole, "freshRecorder already has RECORDER_ROLE").to.be.false;
      
        // Grant RECORDER_ROLE to freshRecorder
        const tx = await zkVerifier.connect(admin).grantRole(RECORDER_ROLE, freshRecorder.address);
        await tx.wait();
      
        // Verify freshRecorder has RECORDER_ROLE
        expect(
          await zkVerifier.hasRole(RECORDER_ROLE, freshRecorder.address),
          "freshRecorder did not receive RECORDER_ROLE"
        ).to.be.true;
      
        // Test recording with freshRecorder
        const id = ethers.utils.formatBytes32String("test33_asset13");
        const content = "Test RECORDER_ROLE";
        const msg = BigNumber.from(
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(content))
        ).mod(snarkScalarField);
      
        // Validate inputs
        expect(snarkScalarField, "snarkScalarField is undefined").to.not.be.undefined;
        expect(msg, "msg is undefined").to.not.be.undefined;
        expect(eddsa.scalarPubKey[0], "eddsa.scalarPubKey[0] is undefined").to.not.be.undefined;
        expect(eddsa.scalarPubKey[1], "eddsa.scalarPubKey[1] is undefined").to.not.be.undefined;
      
        const signature = await eddsa.sign(msg);
        expect(signature, "signature is undefined").to.not.be.undefined;
        expect(signature.S, "signature.S is undefined").to.not.be.undefined;
        expect(signature.R8, "signature.R8 is undefined").to.not.be.undefined;
        expect(signature.R8[0], "signature.R8[0] is undefined").to.not.be.undefined;
        expect(signature.R8[1], "signature.R8[1] is undefined").to.not.be.undefined;
      
        expect(eddsa.babyjub.F, "eddsa.babyjub.F is undefined").to.not.be.undefined;
        const r8x = eddsa.babyjub.F.toObject(signature.R8[0]);
        const r8y = eddsa.babyjub.F.toObject(signature.R8[1]);
        expect(r8x, "r8x is undefined").to.not.be.undefined;
        expect(r8y, "r8y is undefined").to.not.be.undefined;
      
        const proof = await client.prove({
          M: msg.toBigInt(),
          Ax: eddsa.scalarPubKey[0],
          Ay: eddsa.scalarPubKey[1],
          S: signature.S,
          R8x: r8x,
          R8y: r8y,
        });
        expect(proof, "proof is undefined").to.not.be.undefined;
      
        const validSignals: [BigNumber, BigNumber, BigNumber] = [
          msg,
          BigNumber.from(eddsa.scalarPubKey[0]),
          BigNumber.from(eddsa.scalarPubKey[1]),
        ];
      
        // Record proof with freshRecorder
        const recordTx = await zkVerifier.connect(freshRecorder).record(id, validSignals, proof);
        const receipt = await recordTx.wait();
      
        // Verify RecordAdded event
        const event = receipt.events?.find(e => e.event === "RecordAdded");
        expect(event, "RecordAdded event not emitted").to.exist;
        expect(event?.args?.id).to.equal(id);
      
        // Verify records mapping
        expect(await zkVerifier.records(id, 0)).to.equal(validSignals[0]);
        expect(await zkVerifier.records(id, 1)).to.equal(validSignals[1]);
        expect(await zkVerifier.records(id, 2)).to.equal(validSignals[2]);
    });
});
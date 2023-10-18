"use client";

import { Client, UserOperationBuilder } from "userop";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import base64 from "@hexagon/base64";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifiedRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import * as cborx from "cbor-x";
import { useState } from "react";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import axios from "axios";
import Image from "next/image";
import { ethers } from "ethers";
import {
  EntryPoint__factory,
  SimpleAccountFactory__factory,
  SimpleAccount__factory,
} from "@account-abstraction/contracts";

enum TransactionStage {
  Unsent,
  SigningChallenge,
  CreatingProof,
  VerifyingProof,
  GeneratingUserOp,
  SendingUserOp,
  QueryingForReceipts,
  Confirmed,
}

const encoder = new cborx.Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
});

/**
 * Decode from a Base64URL-encoded string to an ArrayBuffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials.
 *
 * @param buffer Value to decode from base64
 * @param to (optional) The decoding to use, in case it's desirable to decode from base64 instead
 */
export function toBuffer(
  base64urlString: string,
  from: "base64" | "base64url" = "base64url"
): Uint8Array {
  const _buffer = base64.toArrayBuffer(base64urlString, from === "base64url");
  return new Uint8Array(_buffer);
}

export function decodeFirst<Type>(input: Uint8Array): Type {
  const decoded = encoder.decodeMultiple(input) as undefined | Type[];

  if (decoded === undefined) {
    throw new Error("CBOR input data was empty");
  }

  /**
   * Typing on `decoded` is `void | []` which causes TypeScript to think that it's an empty array,
   * and thus you can't destructure it. I'm ignoring that because the code works fine in JS, and
   * so this should be a valid operation.
   */
  // @ts-ignore 2493
  const [first] = decoded;

  return first;
}

function toDataView(array: Uint8Array): DataView {
  return new DataView(array.buffer, array.byteOffset, array.length);
}

export function parseAuthenticatorData(authData: Uint8Array) {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`
    );
  }

  let pointer = 0;
  const dataView = toDataView(authData);

  const rpIdHash = authData.slice(pointer, (pointer += 32));

  const flagsBuf = authData.slice(pointer, (pointer += 1));
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array | undefined = undefined;
  let credentialID: Uint8Array | undefined = undefined;
  let credentialPublicKey: Uint8Array | undefined = undefined;
  let credentialPublicKeyDecoded: Uint8Array | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, (pointer += 16));

    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    credentialID = authData.slice(pointer, (pointer += credIDLen));

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = decodeFirst(authData.slice(pointer));
    const firstEncoded = Uint8Array.from(encoder.encode(firstDecoded));

    credentialPublicKey = firstEncoded;
    credentialPublicKeyDecoded = firstDecoded as any;
    pointer += firstEncoded.byteLength;
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    credentialPublicKeyDecoded,
  };
}

function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export default function Home() {
  const API_URL =
    process.env.NODE_ENV === "production"
      ? "https://proving-server.onrender.com"
      : "http://localhost:8000";
  const [username, setUsername] = useState("");
  const [response, setResponse] = useState<VerifiedRegistrationResponse>();
  const [txHash, setTxHash] = useState("");
  const [stage, setStage] = useState(TransactionStage.Unsent);
  const [error, setError] = useState("");

  async function loginCredential() {
    if (
      stage !== TransactionStage.Unsent &&
      stage !== TransactionStage.Confirmed
    ) {
      return;
    }
    setError("");
    try {
      setStage(TransactionStage.SigningChallenge);
      const authenticationOptions = await generateAuthenticationOptions({
        rpID: window.location.hostname,
        challenge: "asdf",
      });
      const authenticationResponse = await startAuthentication(
        authenticationOptions
      );
      const clientDataJSON = base64.toArrayBuffer(
        authenticationResponse.response.clientDataJSON,
        true
      );
      const authenticatorData = base64.toArrayBuffer(
        authenticationResponse.response.authenticatorData,
        true
      );
      const signature = base64.toArrayBuffer(
        authenticationResponse.response.signature,
        true
      );

      const hashedClientData = await window.crypto.subtle.digest(
        "SHA-256",
        clientDataJSON
      );
      const preimage = concatUint8Arrays(
        new Uint8Array(authenticatorData),
        new Uint8Array(hashedClientData)
      );
      const hashedMessage = await window.crypto.subtle.digest(
        "SHA-256",
        preimage
      );

      console.log({
        clientDataJSON,
        authenticationOptions,
        authenticationResponse,
        parsed,
        hashedMessage,
        hashedClientData,
        preimage,
        signature: new Uint8Array(signature),
      });

      const fetched = localStorage.getItem(authenticationResponse.id);
      if (!fetched) {
        throw new Error("Credential not stored. Please try registering again!");
      }

      const authenticator = JSON.parse(fetched);
      console.log({ authenticator });

      const publicKey = decodeFirst<any>(
        Uint8Array.from(authenticator.credentialPublicKey)
      );
      const kty = publicKey.get(1);
      const alg = publicKey.get(3);
      const crv = publicKey.get(-1);
      const x = publicKey.get(-2);
      const y = publicKey.get(-3);
      const n = publicKey.get(-1);

      const keyData = {
        kty: "EC",
        crv: "P-256",
        x: base64.fromArrayBuffer(x, true),
        y: base64.fromArrayBuffer(y, true),
        ext: false,
      };

      const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
      let rBytes = new Uint8Array(parsedSignature.r);
      let sBytes = new Uint8Array(parsedSignature.s);

      if (shouldRemoveLeadingZero(rBytes)) {
        rBytes = rBytes.slice(1);
      }

      if (shouldRemoveLeadingZero(sBytes)) {
        sBytes = sBytes.slice(1);
      }

      // const finalSignature = isoUint8Array.concat([rBytes, sBytes]);
      const updatedSignature = concatUint8Arrays(rBytes, sBytes);

      const key = await window.crypto.subtle.importKey(
        "jwk",
        keyData,
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        false,
        ["verify"]
      );

      const result = await window.crypto.subtle.verify(
        { hash: { name: "SHA-256" }, name: "ECDSA" },
        key,
        updatedSignature,
        preimage
      );
      console.log({ result, updatedSignature });

      const verifyResponse = await verifyAuthenticationResponse({
        response: authenticationResponse,
        expectedChallenge: "YXNkZg",
        expectedOrigin: window.location.origin,
        expectedRPID: window.location.hostname,
        authenticator: {
          credentialID: Uint8Array.from(authenticator.credentialID),
          credentialPublicKey: Uint8Array.from(
            authenticator.credentialPublicKey
          ),
          counter: authenticator.counter,
        },
      });
      console.log("AUTH", {
        authenticationOptions,
        authenticationResponse,
        verifyResponse,
      });
      // Inputs need to be little-endian
      setStage(TransactionStage.CreatingProof);
      const { data: proof } = await axios.post(`${API_URL}/prove_evm`, {
        r: Array.from(new Uint8Array(rBytes)).reverse(),
        s: Array.from(new Uint8Array(sBytes)).reverse(),
        pubkey_x: Array.from(new Uint8Array(x)).reverse(),
        pubkey_y: Array.from(new Uint8Array(y)).reverse(),
        msghash: Array.from(new Uint8Array(hashedMessage)).reverse(),
        proving_key_path: "./keys/proving_key.pk",
      });

      setStage(TransactionStage.GeneratingUserOp);
      const SIMPLE_ACCOUNT_FACTORY_ADDRESS =
        "0xDb53929659505D0979FcC0ec9889e373a62eeE32";
      const baseGoerliProvider = new ethers.providers.StaticJsonRpcProvider(
        "https://base-goerli.public.blastapi.io/"
      );

      const p256AccountFactoryInterface = new ethers.utils.Interface([
        "function createAccount(bytes memory publicKey) public returns (P256Account ret)",
      ]);
      const simpleAccountFactory = SimpleAccountFactory__factory.connect(
        SIMPLE_ACCOUNT_FACTORY_ADDRESS,
        baseGoerliProvider
      );

      let initCodeForDeploy = ethers.utils.hexConcat([
        SIMPLE_ACCOUNT_FACTORY_ADDRESS,
        p256AccountFactoryInterface.encodeFunctionData("createAccount", [
          "0xc8f2654a5e01bc2732c1b29dc1bd8b57515fd878",
        ]),
      ]);

      console.log("initCode:", initCodeForDeploy);

      const ENTRY_POINT_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

      const entryPoint = EntryPoint__factory.connect(
        ENTRY_POINT_ADDRESS,
        baseGoerliProvider
      );

      const senderAddress = await entryPoint.callStatic
        .getSenderAddress(initCodeForDeploy)
        .then((data) => {
          console.error("Sender addressed returned:", data);
          throw new Error("Expected getSenderAddress() to revert");
        })
        .catch((e) => {
          const data = e.message.match(/0x6ca7b806([a-fA-F\d]*)/)?.[1];
          console.log("caught", e);
          if (!data) {
            return Promise.reject(new Error("Failed to parse revert data"));
          }
          const addr = ethers.utils.getAddress(`0x${data.slice(24, 64)}`);
          return Promise.resolve(addr);
        });

      const nonce = await entryPoint.getNonce(
        senderAddress,
        Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)
      );

      const code = await baseGoerliProvider.getCode(senderAddress);
      console.log({ senderAddress, code });
      const needsDeploy = code === "0x";

      console.log("Calculated sender address:", senderAddress);

      const to = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"; // vitalik
      const value = 0;
      const data = "0x68656c6c6f"; // "hello" encoded to utf-8 bytes

      const simpleAccount = SimpleAccount__factory.connect(
        senderAddress,
        baseGoerliProvider
      );

      const callData = simpleAccount.interface.encodeFunctionData("execute", [
        to,
        value,
        data,
      ]);

      console.log("Generated callData:", callData);

      // FILL OUT REMAINING USER OPERATION VALUES
      const gasPrice = await baseGoerliProvider.getGasPrice();
      console.log({ gasPrice });

      const userOperation = {
        sender: senderAddress,
        nonce: nonce.toHexString(),
        initCode: needsDeploy ? initCodeForDeploy : "0x",
        callData,
        callGasLimit: ethers.utils.hexlify(900_000), // hardcode it for now at a high value
        verificationGasLimit: ethers.utils.hexlify(900_000), // hardcode it for now at a high value
        preVerificationGas: ethers.utils.hexlify(900_000), // hardcode it for now at a high value
        maxFeePerGas: ethers.utils.hexlify(gasPrice),
        maxPriorityFeePerGas: ethers.utils.hexlify(gasPrice),
        paymasterAndData: "0x",
        signature: "0x",
      };
      console.log({ userOperation });

      // REQUEST PIMLICO VERIFYING PAYMASTER SPONSORSHIP
      const chain = "base-goerli"; // find the list of chain names on the Pimlico verifying paymaster reference page
      const apiKey = "0803ac63-0ae7-417f-8b46-ea189ea29cca";

      const pimlicoEndpoint = `https://api.pimlico.io/v1/${chain}/rpc?apikey=${apiKey}`;

      const pimlicoProvider = new ethers.providers.StaticJsonRpcProvider(
        pimlicoEndpoint
      );

      const paymasterAndData = "0xc059f997624fd240214c025e8bb5572e7c65182e";

      userOperation.paymasterAndData = paymasterAndData;

      // console.log("Pimlico paymasterAndData:", paymasterAndData);

      userOperation.signature = "0x" + proof;

      console.log("UserOperation signature:", signature);
      setStage(TransactionStage.SendingUserOp);

      // SUBMIT THE USER OPERATION TO BE BUNDLED
      const userOperationHash = await pimlicoProvider.send(
        "eth_sendUserOperation",
        [userOperation, ENTRY_POINT_ADDRESS]
      );

      console.log("UserOperation hash:", userOperationHash);

      setStage(TransactionStage.QueryingForReceipts);
      // let's also wait for the userOperation to be included, by continually querying for the receipts
      console.log("Querying for receipts...");
      let receipt = null;
      while (receipt === null) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        receipt = await pimlicoProvider.send("eth_getUserOperationReceipt", [
          userOperationHash,
        ]);
        console.log(receipt === null ? "Still waiting..." : receipt);
      }

      const txHash = receipt.receipt.transactionHash;
      setStage(TransactionStage.Confirmed);
      setTxHash(txHash);

      console.log(
        `UserOperation included: https://goerli.basescan.org/tx/${txHash}`
      );
    } catch (e) {
      setError((e as any).message || "An unknown error occurred");
    }
  }

  async function createNewCredential() {
    if (
      stage !== TransactionStage.Unsent &&
      stage !== TransactionStage.Confirmed
    ) {
      return;
    }
    setError("");
    try {
      const generatedRegistrationOptions = await generateRegistrationOptions({
        rpName: "demo",
        rpID: window.location.hostname,
        userID: username || "Based Account",
        userName: username || "Based Account",
        attestationType: "direct",
        challenge: "asdf",
        supportedAlgorithmIDs: [-7],
      });
      const startRegistrationResponse = await startRegistration(
        generatedRegistrationOptions
      );
      const verificationResponse = await verifyRegistrationResponse({
        response: startRegistrationResponse,
        expectedOrigin: window.location.origin,
        expectedChallenge: generatedRegistrationOptions.challenge,
        supportedAlgorithmIDs: [-7],
      });
      console.log("REGISTER", {
        generatedRegistrationOptions,
        startRegistrationResponse,
        verificationResponse,
        authDataParsed: parseAuthenticatorData(
          decodeFirst<any>(
            toBuffer(startRegistrationResponse.response.attestationObject)
          ).get("authData")
        ),
      });
      setResponse(verificationResponse);
      if (!verificationResponse.registrationInfo) {
        return;
      }
      const { id } = startRegistrationResponse;
      const { credentialID, credentialPublicKey, counter } =
        verificationResponse.registrationInfo;

      const publicKey = decodeFirst<any>(credentialPublicKey);
      const kty = publicKey.get(1);
      const alg = publicKey.get(3);
      const crv = publicKey.get(-1);
      const x = publicKey.get(-2);
      const y = publicKey.get(-3);
      const n = publicKey.get(-1);

      localStorage.setItem(
        id,
        JSON.stringify({
          credentialID: Array.from(credentialID),
          credentialPublicKey: Array.from(credentialPublicKey),
          counter,
        })
      );
      localStorage.setItem("user-registered", "true");
    } catch (e) {
      setError((e as any).message || "An unknown error occured");
    }
  }

  // const isRegistered = localStorage.getItem("user-registered") === "true";

  return (
    <div className="w-screen h-screen flex justify-center items-center dark:bg-black  bg-gray-200">
      <div className="flex flex-col items-center border-gray-200 border rounded-md py-8 px-4 gap-6 m-6">
        <Image width={80} height={80} src="/touchID.png" alt="Touch ID" />
        <h1 className="text-3xl font-bold text-orange-700">ZK Face ID</h1>
        <div className="text-center text-gray-900 dark:text-white">
          <p>Send Ethereum transactions directly in the browser.</p>
        </div>
        <button
          className={`text-black font-bold py-2 px-4 rounded-md bg-white ${
            username ? "cursor-pointer hover:opacity-80" : ""
          }`}
          onClick={createNewCredential}
        >
          Register new account
        </button>
        {
          <button
            // disabled={loading}
            className="cursor-pointer hover:opacity-80 text-white font-bold py-2 px-4 rounded bg-transparent border"
            onClick={loginCredential}
          >
            Sign transaction
          </button>
        }
        {error && <p className="text-red-500">{error}</p>}
        {stage !== TransactionStage.Confirmed &&
          stage !== TransactionStage.Unsent &&
          !error && (
            <p className="flex gap-3 items-center">
              <>
                {stage === TransactionStage.SigningChallenge &&
                  "Signing WebAuthn challenge..."}
                {stage === TransactionStage.CreatingProof &&
                  "Generating P256 proof..."}
                {stage === TransactionStage.VerifyingProof &&
                  "Verifying proof..."}
                {stage === TransactionStage.GeneratingUserOp &&
                  "Building UserOperation..."}
                {stage === TransactionStage.SendingUserOp &&
                  "Sending to bundler..."}
                {stage === TransactionStage.QueryingForReceipts &&
                  "Sent, querying for receipts..."}
              </>
              <svg
                aria-hidden="true"
                className="inline w-4 h-4 mr-2 text-gray-200 animate-spin dark:text-gray-600 fill-gray-600 dark:fill-gray-300"
                viewBox="0 0 100 101"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z"
                  fill="currentColor"
                />
                <path
                  d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z"
                  fill="currentFill"
                />
              </svg>
            </p>
          )}
        {stage === TransactionStage.Confirmed && (
          <p className="underline cursor-pointer">
            <a
              target="_blank"
              href={`https://goerli.basescan.org/tx/${txHash}`}
            >
              Transaction confirmed at 0x{txHash.slice(0, 3)}...
              {txHash.slice(-2)} ✅
            </a>
          </p>
        )}
        {response?.registrationInfo &&
          !error &&
          stage === TransactionStage.Unsent && (
            <p>Registered new credential ✅</p>
          )}
      </div>
    </div>
  );
}

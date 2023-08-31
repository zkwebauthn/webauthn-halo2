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
      const parsed = parseAuthenticatorData(new Uint8Array(authenticatorData));

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
        throw new Error(`Not stored for ${authenticationResponse.id}`);
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
      console.log({ x, y, crv, alg });

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

      const response = await verifyAuthenticationResponse({
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
      console.log({ response });
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
        "0x702AB84954aC4332718AA1297F7A9c94218c18EB";
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

      userOperation.signature =
        "0x29f998a79ad54d561f202d10c32031f607f7fa931b77f5cbf89b38076592be9a0895aa5203308541af5b2e0dc22bef9cec3ad08e4d9c9b1bbef7324df6fe45a81115c7b29d8cffe93b17927d06bd9487f341ceae76d61c23acdfda419065e6352c4795e2b426fdfd9249004b4aa2e64c677788ef2188e67a6732983ad5da2c462628d45d3a082a46f41ed0c6a2dde9bdaab5983bf2869f25b21afe2e4c2110390d60b846f86cd6ee2483995f1ccc8618eb9009c1239a954d5d8e07394f98934829ec28d4bfded92e01afc92c3beb0461742d38123f175998b6bd80e96bb2cd210bf330f9d106ccff8e4ecd9ae2efe546ef2bd7a4c0a43af444591399e5cd7dea0ddbec375fa3bd57180f1474856c330844b99beb8bbfd2f7b667e679374af30c280832199f21e17a27a23ad86399b7c715770307db342b6c19523610c48248692e145515fa73e001aa804fae90f8363c5a3c80e4a7bd717d6f08e0bea701283028eae1bbdd2c195d5c538eaad1f827ecade6e4b2d04a602c03f9048b0e9378bd1d9dd34ec7cd389f6066ca7e29b60ff6c223a77f5e285b22759ee83a2474c88b2402e45816b14132c60b9463f9f2fe743c1c368a47615c3f770fd656e8fdfc762bf17128729f6efb5bd05c666cb2e3bbf2598797c9a451679cdcb3f02594756e08633ef9fa3b36412b29765b96191e4006350af9e136997e14f9a89b632094e71d1e68ceccfa8d5ecf9b9446ffd1aff91168f78b192b9c12bbc23d5e0474105613f45aec77260bfe5637dd2eb1eaabcf0e92c317940a3ddbd6d50e67ada8f67e185e8b698d53b352d0a64e10404fe44b9a85b1898ac4712a389224029734a11a1d362d976d6bda11fd56ac84827c660077e2f893bf7a2b18a0217087642ed4690d26b838a549e1940455aa2627f171864bc7083dc5673b06f17fb9147840867b06c33f55e2a42aa487cb5b0604b509246ff8f68978ac8b66c55b661f4a45d0e00fba845525372b874cea2767e431fe03dd36c2af563bf94cb9ecd0d2dc48dc2a200b151295886090d20b567806f7c6e3c2b4147d44cf395c8766a4cc3ddc52d5245368fe43088cbd2f574b24d9fcd9d2ed519efa83a7958296dbd91629b11a3703b7ab2d0b8223d7128edd8043e85661d8928b5929fd18da11d54c5c515868c32fe40d3bb45e2967dc616df4fd3fef2c3f72c13f5eb7d8516c43d604b1d5cf2224a177344796b41eeeab8cca7c1f182b66e1025efaa76f88a406fee98ea8e9392d54b900e3c158fca9bdc5498d1ccfc8873d5f61b648c73145961b3a16390e860e1bb2fe95e5e2a92fe74f35317bd2a64da8c52a1a9eb807ca689a270517dd320f74e37dfcf3c9e8b785a77457a01df6bb626ccbec32b6ad193fdc8ec7a3a9bb105eb0d726d6293ac555ffb339760f8660c6f9e8480c565e7324933015d7d3c70746939df0f749ffeb12087425c26975ca212b507610c83e490d6e583d7869991ddda9931e6d508f8232eb650b8847930c8851e3912dff5b1d1605d7e3c1e8322d5d99670916c19d6597aa80b91e0ef2371745cd31cc42b13fcfa562ff30397f2aeed2c175358b657a721c17de12bedb350d58683001fc330afeea155488248919c857f0d216cd3d05662f79d42bfb63f93441eee1a07ba7b0058fa20b9e0d232e8398eb0b0454cafbd2fa501797cc43a05fb25609e4c2e86e6a5f5dff40e17512fa1f8db6235c1f2a35c3b87b62b4fa54d598f9fda14493cc290972ce9f90531a0b90534f982fe696408dd56474e2fc10b5eeed0939d6edb41d28bd4260f1d3047e9148a846fad8a909c64b67cf3dc0146a95f53d64dc4f7d59a799732414f118656c36ecd754a6e71b6e66ceb8367bb668a73a059d8abee5ad9f4eabf4c5592eeca4b396bb47333b7f7825d33a65134fe2d6d7d0289f9216998a321f95f2831b42eccbb297611dfcf7bb76bf54534123814b66f9acc77fed96780fef4705de2d4557333a7438b2851fe0bd7432ef1826afd39873a064788c26c05afb1f6acd23a0b37c1054d1be54c78bdd823e42c85043f91ec3c32ccd72bf08cf7fa8a47c28bdaafe20843fef3b3397428cef3794b03b9148e993b7ef8c8ee45bef6a181c27b3c2c46010595a6f6631a36b3b519f9136d4be2cd805a99f26dbdd1956ccba161c633f4e0afe17d2118364d66ded970fe925508f95eef5a8c5a2c8076128c127368f1ece7f766f49d51b179fed1fcd8690a47d03f2bd588bd826500e68cd6e1b2910465ea372f8f601e926c143137a588c5ce4d9eb5fda9bf0910eedf3d11c29ddbefd64745f8225ccc1a08be570560452552a84ef332958ec7d86641e4a652be177680396a72eee29f48b30e439ea654d319c3599166a1d593943752a232e17c170baafff14b5b775d7d0d30a3335e162a9fcc28f30f0496733ac8a73e2f2279abce417264607348b22f158eee77a26b73eacfeaf4355a2edb48a4a04a69929238960c736a57e796a5a4ac083c80e34e2cc0461b564868847a6546bc285a314503720f252764d12e0b5590e2e46b8fec06a20da5a5e8fc5e1ccbc3b2bc3ca146656b8300794597f0b87bf9d2eb422fe5513653d41323780e99a1be9a41dcb0bfb714f59e20291a8b805701f6e435cb8e73370b1253c3ec891fe4116040b0d0cd8a7ac0a6727a532cc194f5cbb9cfbfeb4d62f9b497a8b1966c18abdcfd55f1390eedd2297804cc244b25b7e393b1b8b462e502a69da1a271303a659454c5302e0aa9b3ef23e545ea521627df794bbb9ee19fdb57768a08c732ecdeb34189d2809795980d21b95a2f9d0c749100835496bf275ea7d743e4a7b8934fa4478d325de51b68af9d95d098f4540163a5be3e6c2669772f80685aff588738d5f6f7a1e8799d581605ad52efa87b498ccea2149298b0b25f49e54789fbfe1341d1e2f02c0331954b5bb5fdfccd635da25d32c7c5fce3ad1ed1985056b5f970db2471100152fe7976a1705d08e352254025f35d99b3ef397869067eaef3e1465d53c65122e2e7d3a202e7530b79bf7732447ce9068bc7fe2e251a59b590db402bcc115173a8ff64a04e2e02af6f00cfb70e4694b3f0608b85d917bedc9fb26191b49c213777ccdaee976412d326555b43335e28029b403741fc5024e23fd728485c538259eedc5b53d730ed34f8d23b27bb2a03dcf19f09fa493db193b6a3fe94938f423844733f3913b8bba732ba2456300ad72a52243c47c7d558106f42dea19032e1383abf6df27e38b2a4215ba88d1982099355cda05a2aa9e30a7da9c732902d818f04018b716975721599e11efd78e28c19ee508955c3f276edf2d58de2e3cfb2b802812ebfd3cc54cad11b78c27700cc2f184312b0aae93c16c90f51915e500109c0b4fc83f42d1d288a89b7c6c51f9fc41b258d99cc6d93b9d947df86ff9142f32c35ca02a67e9e2eebef3f467d085e03c5d47862678271075eeb8d1cbd08417b8799e11c592f947e579451f1027b3d8515d9f36236a43d6b15fbe8fbaf5820a151a0c905e61c1e6b098c99341d5ae0b24028d57567682f70faaddc936cad00f8e150818e7a3bcd46b0f51a7821e862e264f2b0cf2ac7ae791f1028ab8942526222fef01f17b71531ff140f0224378d369697df067bb7ec2e46d945273394906df43dcb812e7ea06e486de959b0bd4c7d1334010cb7be83f4c7c3cab8996072d5044c058e43f5700ba7f287d542d4a1daa7077b6496d0b6eedc129778c10b72f3737d49033de9a7b6f7272d1ad2317cb5aa706fa8649e10d723a7101d8dd74246ea0ded2552e6b85f959b9fb9425878cf17ec529a89b8af35042edb0c7e1a9";

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
        userID: username || "user",
        userName: username || "user",
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
    <div className="w-screen h-screen flex justify-center items-center">
      <div className="flex flex-col items-center border-gray-200 border rounded-md p-8 gap-6">
        <Image width={80} height={80} src="/touchID.png" alt="Touch ID" />
        <h1 className="text-3xl font-bold text-orange-700">Passkey Wallet</h1>
        <div className="text-center">
          <p>Send Ethereum transactions with just your fingerprint.</p>
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
                  "Sending UserOperation to bundler..."}
                {stage === TransactionStage.QueryingForReceipts &&
                  "UserOperation sent, querying for receipts..."}
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
              Transaction confirmed at 0x{txHash.slice(0, 4)}...
              {txHash.slice(-3)} ✅
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

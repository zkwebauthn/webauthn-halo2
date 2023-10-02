import base64 from "@hexagon/base64";
import { startAuthentication } from "@simplewebauthn/browser";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import {
  concatUint8Arrays,
  decodeFirst,
  parseAuthenticatorData,
  shouldRemoveLeadingZero,
} from "./utils";
import axios from "axios";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";

const API_URL =
  process.env.NODE_ENV === "production"
    ? "https://proving-server.onrender.com"
    : "http://localhost:8000";

interface PasskeyArgs {
  apiKey: string;
  chainId: number;
  publicKey: string;
}

export class Passkey {
  private _chainId: number;
  private _apiKey: string;
  private _publicKey: string;
  private _credentialPublicKey: Uint8Array;

  constructor(args: PasskeyArgs) {
    this._apiKey = args.apiKey;
    this._chainId = args.chainId;
    this._publicKey = args.publicKey;
  }

  public get publicKey() {
    return this._publicKey;
  }

  public async signRecoveryChallenge(expectedChallenge: string) {
    const authenticationOptions = await generateAuthenticationOptions({
      rpID: window.location.hostname,
      challenge: expectedChallenge,
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

    // Check
    const publicKey = decodeFirst<any>(this._credentialPublicKey);

    const x = publicKey.get(-2);
    const y = publicKey.get(-3);

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

    const { data: proof } = await axios.post(`${API_URL}/prove_evm`, {
      r: Array.from(new Uint8Array(rBytes)).reverse(),
      s: Array.from(new Uint8Array(sBytes)).reverse(),
      pubkey_x: Array.from(new Uint8Array(x)).reverse(),
      pubkey_y: Array.from(new Uint8Array(y)).reverse(),
      msghash: Array.from(new Uint8Array(hashedMessage)).reverse(),
      proving_key_path: "./keys/proving_key.pk",
    });
    return proof;
  }
}

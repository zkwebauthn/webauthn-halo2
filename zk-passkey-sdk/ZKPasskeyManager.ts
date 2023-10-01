import {
  GenerateRegistrationOptionsOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { Passkey } from "./Passkey";
import { startRegistration } from "@simplewebauthn/browser";
import { decodeFirst } from "./utils";
import axios from "axios";

const API_URL =
  process.env.NODE_ENV === "production"
    ? "https://proving-server.onrender.com"
    : "http://localhost:8000";

interface ZKPasskeyManagerArgs {
  apiKey: string;
  chainId: number;
}

type RegisterNewPasskeyArgs = Partial<GenerateRegistrationOptionsOpts>;

export class ZKPasskeyManager {
  private _chainId: number;
  private _apiKey: string;

  constructor(args: ZKPasskeyManagerArgs) {
    this._chainId = args.chainId;
    this._apiKey = args.apiKey;
  }

  // Function to register a new passkey
  public async registerNewPasskey(
    args: RegisterNewPasskeyArgs
  ): Promise<Passkey> {
    const generatedRegistrationOptions = await generateRegistrationOptions({
      rpName: args.rpName ?? "ZKPasskeyManager",
      rpID: args.rpID ?? window.location.hostname,
      userID: args.userID ?? "UserID",
      userName: args.userName ?? "username",
      attestationType: "direct",
      challenge: args.challenge ?? "challenge",
      supportedAlgorithmIDs: [-7],
    });
    const startRegistrationResponse = await startRegistration(
      generatedRegistrationOptions
    );
    const verificationResponse = await verifyRegistrationResponse({
      response: startRegistrationResponse,
      expectedOrigin: window.location.origin,
      expectedChallenge: generatedRegistrationOptions.challenge,
      expectedRPID: generatedRegistrationOptions.rp.id,
      supportedAlgorithmIDs: [-7],
    });

    const { id } = startRegistrationResponse;
    const { credentialID, credentialPublicKey, counter } =
      verificationResponse.registrationInfo!;

    const publicKey = decodeFirst<any>(credentialPublicKey);

    // TODO: Call proving server
    // const { data: proof } = await axios.post(`${API_URL}/prove_evm`, {
    //   r: Array.from(new Uint8Array(rBytes)).reverse(),
    //   s: Array.from(new Uint8Array(sBytes)).reverse(),
    //   pubkey_x: Array.from(new Uint8Array(x)).reverse(),
    //   pubkey_y: Array.from(new Uint8Array(y)).reverse(),
    //   msghash: Array.from(new Uint8Array(hashedMessage)).reverse(),
    //   proving_key_path: "./keys/proving_key.pk",
    // });

    return this.fromPublicKey(publicKey);
  }

  public fromPublicKey(publicKey: string): Passkey {
    return new Passkey({
      apiKey: this._apiKey,
      chainId: this._chainId,
      publicKey,
    });
  }
}

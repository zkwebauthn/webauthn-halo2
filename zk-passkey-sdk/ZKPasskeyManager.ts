import {
  GenerateRegistrationOptionsOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { Passkey } from "./Passkey";
import { startRegistration } from "@simplewebauthn/browser";
import { decodeFirst } from "./utils";
import axios from "axios";

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

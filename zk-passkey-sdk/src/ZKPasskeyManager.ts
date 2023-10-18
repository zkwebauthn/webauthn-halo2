import { Passkey } from "./Passkey";
import { startRegistration } from "@simplewebauthn/browser";
import { decodeFirst, parseAuthenticatorData, toBuffer } from "./utils";

interface ZKPasskeyManagerArgs {
  apiKey: string;
}

interface RegisterNewPasskeyArgs {
  challenge?: string;
  rpID?: string;
  rpName?: string;
  userID?: string;
  userName?: string;
}

export class ZKPasskeyManager {
  private _apiKey: string;

  constructor(args: ZKPasskeyManagerArgs) {
    this._apiKey = args.apiKey;
  }

  // Function to register a new passkey
  public async registerNewPasskey(
    args: RegisterNewPasskeyArgs
  ): Promise<Passkey> {
    const startRegistrationResponse = await startRegistration({
      challenge: args.challenge ?? "challenge",
      attestation: "direct",
      pubKeyCredParams: [
        {
          alg: -7,
          type: "public-key",
        },
      ],
      rp: {
        id: args.rpID ?? window.location.hostname,
        name: args.rpName ?? "ZKPasskeyManager",
      },
      user: {
        id: args.userID ?? "UserID",
        name: args.userName ?? "username",
        displayName: args.userName ?? "username",
      },
    });

    const authData = decodeFirst<any>(
      toBuffer(startRegistrationResponse.response.attestationObject)
    ).get("authData");
    const { credentialPublicKey } = parseAuthenticatorData(authData);
    if (!credentialPublicKey) {
      throw new Error("Invalid auth data from WebAuthn registration");
    }

    return this.fromPublicKey(credentialPublicKey);
  }

  public fromPublicKey(publicKey: Uint8Array): Passkey {
    return new Passkey({
      apiKey: this._apiKey,
      publicKey,
    });
  }
}

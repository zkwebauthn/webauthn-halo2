import {
  GenerateRegistrationOptionsOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { Passkey } from "./Passkey";
import { startRegistration } from "@simplewebauthn/browser";
import { decodeFirst } from "./utils";

interface ZKPasskeyManagerArgs {
  apiKey: string;
  chainId: number;
}

type RegisterNewPasskeyArgs = Partial<GenerateRegistrationOptionsOpts>;

class ZKPasskeyManager {
  private chainId: number;
  private apiKey: string;

  constructor(args: ZKPasskeyManagerArgs) {
    this.chainId = args.chainId;
    this.apiKey = args.apiKey;
  }

  // Function to register a new passkey
  async registerNewPasskey(args: RegisterNewPasskeyArgs): Promise<Passkey> {
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
      verificationResponse.registrationInfo;

    const publicKey = decodeFirst<any>(credentialPublicKey);
  }

  fromPublicKey(publicKey: string): Passkey {
    // TODO
  }
}

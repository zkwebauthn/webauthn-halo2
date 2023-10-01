interface PasskeyArgs {
  apiKey: string;
  chainId: number;
  publicKey: string;
}

export class Passkey {
  private _chainId: number;
  private _apiKey: string;
  private _publicKey: string;

  constructor(args: PasskeyArgs) {
    this._apiKey = args.apiKey;
    this._chainId = args.chainId;
    this._publicKey = args.publicKey;
  }

  public get publicKey() {
    return this._publicKey;
  }

  public async signRecoveryChallenge() {
    // TODO
  }
}

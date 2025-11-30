import { ASSERT } from "../../utilities/util";
import crypto from "crypto";
import BN from "bn.js";

export type Salt = Buffer;
export type Verifier = Buffer;
export type EphemeralKey = Buffer;
export type SessionKey = Buffer;

export class SRP6 {
  #used = false;

  // Constants
  public static readonly SALT_LENGTH = 32;
  public static readonly VERIFIER_LENGTH = 32;
  public static readonly EPHEMERAL_KEY_LENGTH = 32;
  public static readonly DIGEST_LENGTH = 20; // SHA1 digest length

  public static readonly g = Buffer.from([7]);
  public static readonly N = Buffer.from(
    "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
    "hex"
  );

  public static readonly _g: BN = new BN(this.g);
  public static readonly _N: BN = new BN(this.N);

  // Instance properties
  private readonly _I: Buffer; // H(username)
  private readonly _b: BN; // random secret
  private readonly _v: BN; // verifier as BigNumber

  public readonly s: Salt; // salt
  public readonly B: EphemeralKey; // public ephemeral key

  public static sha1(buff: Buffer): Buffer {
    return crypto.createHash("sha1").update(buff).digest();
  }

  constructor(username: string, salt: string, verifier: string) {
    // Username must be uppercased for I = H(username)
    this._I = this.SHA1(username.toUpperCase());
    this._b = new BN(crypto.randomBytes(32));
    this._v = new BN(Buffer.from(verifier, "hex"));
    this.s = Buffer.from(salt, "hex");
    this.B = this._calculateB(this._b, this._v);
  }

  /**
   * Generate registration data (salt and verifier) for a new user
   * NOTE: username and password should be uppercased before calling this!
   */
  public static MakeRegistrationData(
    username: string,
    password: string
  ): [string, string] {
    const salt = crypto.randomBytes(this.SALT_LENGTH);
    const verifier = this.CalculateVerifier(username, password, salt);

    return [salt.toString("hex"), verifier.toString("hex")];
  }

  /**
   * Check if login credentials are valid
   */
  public static CheckLogin(
    username: string,
    password: string,
    salt: Salt,
    verifier: Verifier
  ): boolean {
    return verifier.equals(this.CalculateVerifier(username, password, salt));
  }

  /**
   * Get session verifier for mutual authentication
   */
  public static GetSessionVerifier(
    A: EphemeralKey,
    clientM: Buffer,
    K: SessionKey
  ): Buffer {
    return this.SHA1(A, clientM, K);
  }

  /**
   * Verify the client's challenge response
   */
  public VerifyChallengeResponse(
    A: EphemeralKey,
    clientM: Buffer
  ): SessionKey | null {
    ASSERT(
      !this.#used,
      "A single SRP6 object must only ever be used to verify ONCE!"
    );
    this.#used = true;

    const _A = new BN(A);

    // Check if A % N == 0 (invalid)
    if (_A.mod(SRP6._N).isZero()) {
      return null;
    }

    // u = H(A || B)
    const u = new BN(this.SHA1(A, this.B));

    // S = (A * v^u) ^ b mod N
    const S = _A
      .mul(this._v.toRed(BN.red(SRP6._N)).redPow(u).fromRed())
      .toRed(BN.red(SRP6._N))
      .redPow(this._b)
      .fromRed()
      .toArrayLike(Buffer, "be", SRP6.EPHEMERAL_KEY_LENGTH);

    // K = SHA1_Interleave(S)
    const K = SRP6.SHA1Interleave(S);

    // Calculate NgHash = H(N) xor H(g)
    const NHash = this.SHA1(SRP6.N);
    const gHash = this.SHA1(SRP6.g);
    const NgHash = Buffer.alloc(SRP6.DIGEST_LENGTH);
    for (let i = 0; i < SRP6.DIGEST_LENGTH; i++) {
      NgHash[i] = NHash[i] ^ gHash[i];
    }

    // ourM = H(NgHash || I || s || A || B || K)
    const ourM = this.SHA1(NgHash, this._I, this.s, A, this.B, K);

    if (ourM.equals(clientM)) {
      return K;
    }

    return null;
  }

  /**
   * Calculate verifier: v = g^H(s || H(username || ":" || password)) mod N
   * NOTE: username and password MUST be uppercase before calling this!
   */
  public static CalculateVerifier(
    username: string,
    password: string,
    salt: Salt
  ): Verifier {
    // Username and password must be uppercased (caller's responsibility)
    const innerHash = this.SHA1(
      username.toUpperCase(),
      ":",
      password.toUpperCase()
    );
    const x = new BN(this.SHA1(salt, innerHash));

    return this._g
      .toRed(BN.red(this._N))
      .redPow(x)
      .fromRed()
      .toArrayLike(Buffer, "be", this.VERIFIER_LENGTH);
  }

  /**
   * SHA1 Interleave function for session key generation
   */
  public static SHA1Interleave(S: EphemeralKey): SessionKey {
    // Split S into two buffers (even and odd indexed bytes)
    const buf0 = Buffer.alloc(this.EPHEMERAL_KEY_LENGTH / 2);
    const buf1 = Buffer.alloc(this.EPHEMERAL_KEY_LENGTH / 2);

    for (let i = 0; i < this.EPHEMERAL_KEY_LENGTH / 2; i++) {
      buf0[i] = S[2 * i];
      buf1[i] = S[2 * i + 1];
    }

    // Find position of first nonzero byte
    let p = 0;
    while (p < this.EPHEMERAL_KEY_LENGTH && S[p] === 0) {
      p++;
    }

    // Skip one extra byte if p is odd
    if (p & 1) {
      p++;
    }

    p = Math.floor(p / 2); // offset into buffers

    // Hash each half starting at first nonzero byte
    const hash0 = this.SHA1(buf0.slice(p));
    const hash1 = this.SHA1(buf1.slice(p));

    // Interleave the two hashes back together
    const K = Buffer.alloc(this.DIGEST_LENGTH * 2);
    for (let i = 0; i < this.DIGEST_LENGTH; i++) {
      K[2 * i] = hash0[i];
      K[2 * i + 1] = hash1[i];
    }

    return K;
  }

  /**
   * Calculate B = 3v + g^b mod N
   */
  private _calculateB(b: BN, v: BN): EphemeralKey {
    const red = BN.red(SRP6._N);
    const gPowB = SRP6._g.toRed(red).redPow(b).fromRed();
    const threeV = v.muln(3);
    const B = gPowB.add(threeV).mod(SRP6._N);

    return B.toArrayLike(Buffer, "be", SRP6.EPHEMERAL_KEY_LENGTH);
  }

  /**
   * SHA1 hash function that accepts multiple inputs
   */
  private static SHA1(...inputs: (string | Buffer)[]): Buffer {
    const hash = crypto.createHash("sha1");
    for (const input of inputs) {
      if (typeof input === "string") {
        hash.update(input, "utf8");
      } else {
        hash.update(input);
      }
    }
    return hash.digest();
  }

  /**
   * Instance SHA1 method
   */
  private SHA1(...inputs: (string | Buffer)[]): Buffer {
    return SRP6.SHA1(...inputs);
  }
}

export function generateSalt() {
  const buffer = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) buffer[i] = Math.floor(Math.random() * 100);
  return buffer;
}

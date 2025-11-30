import * as crypto from "crypto";

// Types for clarity
type Salt = Buffer;
type Verifier = Buffer;
type EphemeralKey = Buffer;
type SessionKey = Buffer;
type Digest = Buffer;

export class SRP6 {
  // Constants
  public static readonly SALT_LENGTH = 32;
  public static readonly VERIFIER_LENGTH = 32;
  public static readonly EPHEMERAL_KEY_LENGTH = 32;
  public static readonly SESSION_KEY_LENGTH = 40;

  // The generator 'g' = 7
  private static readonly g_val = 7n;
  public static readonly g = Buffer.from([7]);

  // The modulus 'N' (Big-endian hex string from C++ code)
  public static readonly N_hex =
    "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7";
  public static readonly N_buff = Buffer.from(SRP6.N_hex, "hex");
  private static readonly N_int = BigInt("0x" + SRP6.N_hex);

  // Instance State
  private _used = false;
  public readonly s: Salt; // salt
  public readonly B: EphemeralKey; // Server Public Key

  // Private parameters
  private readonly _I: Digest; // H(username)
  private readonly _b: bigint; // Server Private Key (random)
  private readonly _v: bigint; // Verifier integer

  constructor(username: string, salt: string, verifier: string) {
    // _I = SHA1(username)
    this._I = crypto.createHash("sha1").update(username.toUpperCase()).digest();

    // _b = Random 32 bytes converted to BigInt
    const bBytes = crypto.randomBytes(32);
    this._b = this.bufferToBigInt(bBytes);

    // _v = verifier converted to BigInt
    this._v = this.bufferToBigInt(Buffer.from(verifier));
    this.s = Buffer.from(salt);

    // B = (k*v + g^b) % N
    // In WoW/AzerothCore, k is hardcoded to 3
    const k = 3n;

    // term1 = g^b % N
    const term1 = SRP6.modPow(SRP6.g_val, this._b, SRP6.N_int);

    // term2 = v * 3
    const term2 = this._v * k;

    // B = (term1 + term2) % N
    const B_int = (term1 + term2) % SRP6.N_int;

    this.B = this.bigIntToBuffer(B_int, 32);
  }

  /**
   * Generates the Salt and Verifier for a new account.
   * Username/Password should be normalized (usually Uppercase) before calling this.
   */
  public static MakeRegistrationData(
    username: string,
    password: string
  ): { salt: string; verifier: string } {
    const salt = crypto.randomBytes(SRP6.SALT_LENGTH).toString("hex");
    const verifier = SRP6.CalculateVerifier(username, password, salt).toString(
      "hex"
    );
    return { salt, verifier };
  }

  /**
   * Calculates v = g ^ H(s || H(u || ':' || p)) mod N
   */
  private static CalculateVerifier(
    username: string,
    password: string,
    salt: string
  ): Verifier {
    // inner = H(username || ':' || password)
    const innerHash = crypto
      .createHash("sha1")
      .update(username)
      .update(":")
      .update(password)
      .digest();

    // x_hash = H(salt || inner)
    const xHash = crypto
      .createHash("sha1")
      .update(salt)
      .update(innerHash)
      .digest();

    // x becomes integer
    // Note: Buffer to BigInt treats buffer as Big Endian
    const x = BigInt("0x" + xHash.toString("hex"));

    // v = g^x % N
    const v = this.modPow(SRP6.g_val, x, SRP6.N_int);

    return this.bigIntToBuffer(v, 32);
  }

  /**
   * Validates the client's proof (A, M1) and generates the Session Key.
   */
  public VerifyChallengeResponse(
    A: EphemeralKey,
    clientM: Digest
  ): SessionKey | null {
    if (this._used) {
      throw new Error(
        "A single SRP6 object must only ever be used to verify ONCE!"
      );
    }
    this._used = true;

    const A_int = this.bufferToBigInt(A);

    // Safety Check: A % N != 0
    if (A_int % SRP6.N_int === 0n) {
      return null;
    }

    // u = H(A || B)
    const uDigest = crypto.createHash("sha1").update(A).update(this.B).digest();

    const u = this.bufferToBigInt(uDigest);

    // S = (A * (v^u % N)) ^ b % N
    const v_pow_u = SRP6.modPow(this._v, u, SRP6.N_int);
    const base = (A_int * v_pow_u) % SRP6.N_int;
    const S_int = SRP6.modPow(base, this._b, SRP6.N_int);

    const S = this.bigIntToBuffer(S_int, 32);

    const K = this.SHA1Interleave(S);

    // Calculate ourM (Server calculated proof)
    // NgHash = H(N) XOR H(g)
    const hN = crypto.createHash("sha1").update(SRP6.N_buff).digest();
    const hg = crypto.createHash("sha1").update(SRP6.g).digest();
    const NgHash = Buffer.allocUnsafe(20);
    for (let i = 0; i < 20; i++) {
      NgHash[i] = hN[i] ^ hg[i];
    }

    // ourM = H(NgHash, I, s, A, B, K)
    const ourM = crypto
      .createHash("sha1")
      .update(NgHash)
      .update(this._I)
      .update(this.s)
      .update(A)
      .update(this.B)
      .update(K)
      .digest();

    if (ourM.equals(clientM)) {
      return K;
    }

    return null;
  }

  /**
   * Calculates the Server Proof (M2) to be sent back to the client.
   * M2 = H(A, M, K)
   */
  public static GetSessionVerifier(
    A: EphemeralKey,
    clientM: Digest,
    K: SessionKey
  ): Digest {
    return crypto
      .createHash("sha1")
      .update(A)
      .update(clientM)
      .update(K)
      .digest();
  }

  // --- Helpers ---

  /**
   * WoW Specific Key Derivation Function.
   * Splits S into two, hashes them, and interleaves the results.
   */
  private SHA1Interleave(S: Buffer): SessionKey {
    // Remove leading zeros to match C++ logic "while (p < len && !S[p])"
    let p = 0;
    while (p < S.length && S[p] === 0) {
      p++;
    }

    // If offset is odd, skip one more byte (C++: if (p & 1) ++p;)
    if (p % 2 !== 0) {
      p++;
    }

    // Logic from C++: p /= 2; (Indices in split arrays)
    // However, it's easier to view S as a byte array and slice it.
    // We act on the original 32 byte buffer S.

    const T = S.subarray(p); // The non-zero part we care about
    const halfLen = Math.floor(T.length / 2);

    const buf0 = Buffer.alloc(halfLen);
    const buf1 = Buffer.alloc(halfLen);

    for (let i = 0; i < halfLen; i++) {
      buf0[i] = T[2 * i + 0];
      buf1[i] = T[2 * i + 1];
    }

    const hash0 = crypto.createHash("sha1").update(buf0).digest();
    const hash1 = crypto.createHash("sha1").update(buf1).digest();

    const K = Buffer.alloc(40); // 2 * SHA1_DIGEST_LENGTH
    for (let i = 0; i < 20; i++) {
      K[2 * i + 0] = hash0[i];
      K[2 * i + 1] = hash1[i];
    }

    return K;
  }

  // Modular Exponentiation (base^exp % mod)
  private static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    let b = base % mod;
    let e = exp;

    while (e > 0n) {
      if ((e & 1n) === 1n) {
        result = (result * b) % mod;
      }
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  }

  // Helper: Buffer (BigEndian) -> BigInt
  private bufferToBigInt(buffer: Buffer): bigint {
    return BigInt("0x" + buffer.toString("hex"));
  }

  // Helper: BigInt -> Buffer (BigEndian, padded)
  private static bigIntToBuffer(num: bigint, byteLength: number): Buffer {
    let hex = num.toString(16);
    if (hex.length % 2) {
      hex = "0" + hex;
    }
    const buff = Buffer.from(hex, "hex");

    // Pad to correct length if necessary
    if (buff.length < byteLength) {
      const padding = Buffer.alloc(byteLength - buff.length);
      return Buffer.concat([padding, buff]);
    }

    // Truncate if too long (unlikely with mod N)
    if (buff.length > byteLength) {
      return buff.subarray(buff.length - byteLength);
    }

    return buff;
  }

  // Instance helper wrapper
  private bigIntToBuffer(num: bigint, byteLength: number): Buffer {
    return SRP6.bigIntToBuffer(num, byteLength);
  }
}

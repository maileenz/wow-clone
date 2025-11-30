import * as net from "net";
import * as crypto from "crypto";
import * as mysql from "mysql2/promise";

// Auth opcodes for WoW 3.3.5a
enum AuthCmd {
  LOGON_CHALLENGE = 0x00,
  LOGON_PROOF = 0x01,
  REALM_LIST = 0x10,
}

enum AuthResult {
  SUCCESS = 0x00,
  FAIL_UNKNOWN0 = 0x01,
  FAIL_UNKNOWN1 = 0x02,
  FAIL_BANNED = 0x03,
  FAIL_UNKNOWN_ACCOUNT = 0x04,
  FAIL_INCORRECT_PASSWORD = 0x05,
}

class SRP6 {
  private static g = BigInt(7);
  private static N = BigInt(
    "0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
  );

  static generateSalt(): Buffer {
    return crypto.randomBytes(32);
  }

  static calculateVerifier(
    username: string,
    password: string,
    salt: Buffer
  ): Buffer {
    const credentials = `${username.toUpperCase()}:${password.toUpperCase()}`;
    const hash1 = crypto.createHash("sha1").update(credentials).digest();
    const hash2 = crypto
      .createHash("sha1")
      .update(Buffer.concat([salt, hash1]))
      .digest();
    const x = BigInt("0x" + hash2.toString("hex"));
    const v = this.modPow(this.g, x, this.N);
    return this.bigIntToBuffer(v, 32);
  }

  private static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
      if (exp % BigInt(2) === BigInt(1)) result = (result * base) % mod;
      exp = exp / BigInt(2);
      base = (base * base) % mod;
    }
    return result;
  }

  private static bigIntToBuffer(num: bigint, size: number): Buffer {
    const hex = num.toString(16).padStart(size * 2, "0");
    return Buffer.from(hex, "hex");
  }
}

class AuthSession {
  username: string = "";
  salt: Buffer = Buffer.alloc(32);
  verifier: Buffer = Buffer.alloc(32);
  b: Buffer = Buffer.alloc(32);
  B: Buffer = Buffer.alloc(32);
  A: Buffer = Buffer.alloc(32);
  sessionKey: Buffer = Buffer.alloc(40);
  M1: Buffer = Buffer.alloc(20);
}

class AuthServer {
  private server: net.Server;
  private db: mysql.Connection | null = null;
  private sessions = new Map<net.Socket, AuthSession>();

  constructor(private port: number, private dbConfig: mysql.ConnectionOptions) {
    this.server = net.createServer(this.handleConnection.bind(this));
  }

  async start() {
    this.db = await mysql.createConnection(this.dbConfig);
    console.log("Connected to database");

    this.server.listen(this.port, () => {
      console.log(`Auth server listening on port ${this.port}`);
    });
  }

  private handleConnection(socket: net.Socket) {
    console.log(`New connection from ${socket.remoteAddress}`);
    const session = new AuthSession();
    this.sessions.set(socket, session);

    socket.on("data", (data) => this.handleData(socket, data));
    socket.on("close", () => {
      console.log("Client disconnected");
      this.sessions.delete(socket);
    });
    socket.on("error", (err) => console.error("Socket error:", err));
  }

  private async handleData(socket: net.Socket, data: Buffer) {
    const opcode = data.readUInt8(0);

    switch (opcode) {
      case AuthCmd.LOGON_CHALLENGE:
        await this.handleLogonChallenge(socket, data);
        break;
      case AuthCmd.LOGON_PROOF:
        await this.handleLogonProof(socket, data);
        break;
      case AuthCmd.REALM_LIST:
        await this.handleRealmList(socket);
        break;
      default:
        console.log(`Unknown opcode: 0x${opcode.toString(16)}`);
    }
  }

  private async handleLogonChallenge(socket: net.Socket, data: Buffer) {
    const session = this.sessions.get(socket)!;

    // Parse username
    const usernameLength = data.readUInt8(33);
    const username = data.slice(34, 34 + usernameLength).toString("utf8");
    session.username = username;

    console.log(`Logon challenge for: ${username}`);

    // Query database for account
    const [rows] = await this.db!.execute(
      "SELECT salt, verifier FROM account WHERE username = ?",
      [username.toUpperCase()]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      this.sendLogonChallengeError(socket, AuthResult.FAIL_UNKNOWN_ACCOUNT);
      return;
    }

    const account = rows[0] as any;
    session.salt = Buffer.from(account.salt, "hex").reverse();
    session.verifier = Buffer.from(account.verifier, "hex").reverse();

    // Generate b and B for SRP6
    session.b = crypto.randomBytes(19);
    const g = BigInt(7);
    const N = BigInt(
      "0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
    );
    const b = BigInt("0x" + session.b.toString("hex"));
    const v = BigInt("0x" + session.verifier.toString("hex"));
    const gb = this.modPow(g, b, N);
    const B = (v * BigInt(3) + gb) % N;
    session.B = this.bigIntToBuffer(B, 32);

    // Build response
    const response = Buffer.alloc(119);
    let offset = 0;
    response.writeUInt8(AuthCmd.LOGON_CHALLENGE, offset++);
    response.writeUInt8(0, offset++); // error
    response.writeUInt8(AuthResult.SUCCESS, offset++);
    session.B.copy(response, offset);
    offset += 32;
    response.writeUInt8(1, offset++); // g length
    response.writeUInt8(7, offset++); // g
    response.writeUInt8(32, offset++); // N length
    Buffer.from(
      "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
      "hex"
    ).copy(response, offset);
    offset += 32;
    session.salt.copy(response, offset);
    offset += 32;
    crypto.randomBytes(16).copy(response, offset);
    offset += 16;
    response.writeUInt8(0, offset); // security flags

    socket.write(response);
    console.log("Sent logon challenge response");
  }

  private sendLogonChallengeError(socket: net.Socket, error: AuthResult) {
    const response = Buffer.alloc(3);
    response.writeUInt8(AuthCmd.LOGON_CHALLENGE, 0);
    response.writeUInt8(0, 1);
    response.writeUInt8(error, 2);
    socket.write(response);
  }

  private async handleLogonProof(socket: net.Socket, data: Buffer) {
    const session = this.sessions.get(socket)!;
    console.log("Logon proof received");

    // Parse client's A and M1
    session.A = data.slice(1, 33);
    const clientM1 = data.slice(33, 53);

    // Calculate session key (S) using SRP6
    const N = BigInt(
      "0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
    );
    const g = BigInt(7);

    const A = BigInt("0x" + session.A.toString("hex"));
    const b = BigInt("0x" + session.b.toString("hex"));
    const v = BigInt("0x" + session.verifier.toString("hex"));

    // Check A % N != 0
    if (A % N === BigInt(0)) {
      console.log("A % N == 0, rejecting");
      const response = Buffer.alloc(2);
      response.writeUInt8(AuthCmd.LOGON_PROOF, 0);
      response.writeUInt8(AuthResult.FAIL_INCORRECT_PASSWORD, 1);
      socket.write(response);
      return;
    }

    // Calculate u = H(A | B)
    const uHash = crypto
      .createHash("sha1")
      .update(session.A)
      .update(session.B)
      .digest();
    const u = BigInt("0x" + uHash.toString("hex"));

    // Calculate S = (A * v^u) ^ b mod N
    const vu = this.modPow(v, u, N);
    const Avu = (A * vu) % N;
    const S = this.modPow(Avu, b, N);
    const SBuffer = this.bigIntToBuffer(S, 32);

    // Calculate session key using SHA1 interleave (AzerothCore method)
    session.sessionKey = this.sha1Interleave(SBuffer);

    // Calculate M1 = H(H(N) xor H(g) | H(username) | s | A | B | K)
    const NBuffer = Buffer.from(
      "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
      "hex"
    );
    const gBuffer = Buffer.from([7]);

    const NHash = crypto.createHash("sha1").update(NBuffer).digest();
    const gHash = crypto.createHash("sha1").update(gBuffer).digest();
    const NgHash = Buffer.alloc(20);
    for (let i = 0; i < 20; i++) {
      NgHash[i] = NHash[i] ^ gHash[i];
    }

    const usernameHash = crypto
      .createHash("sha1")
      .update(session.username.toUpperCase())
      .digest();

    const M1 = crypto
      .createHash("sha1")
      .update(NgHash)
      .update(usernameHash)
      .update(session.salt)
      .update(session.A)
      .update(session.B)
      .update(session.sessionKey)
      .digest();

    // Verify client's M1
    if (!M1.equals(clientM1)) {
      console.log("M1 verification failed - incorrect password");
      const response = Buffer.alloc(2);
      response.writeUInt8(AuthCmd.LOGON_PROOF, 0);
      response.writeUInt8(AuthResult.FAIL_INCORRECT_PASSWORD, 1);
      socket.write(response);
      return;
    }

    // Calculate M2 = H(A | M1 | K)
    const M2 = crypto
      .createHash("sha1")
      .update(session.A)
      .update(M1)
      .update(session.sessionKey)
      .digest();

    const response = Buffer.alloc(32);
    response.writeUInt8(AuthCmd.LOGON_PROOF, 0);
    response.writeUInt8(AuthResult.SUCCESS, 1);
    M2.copy(response, 2);
    response.writeUInt32LE(0, 22); // account flags
    response.writeUInt32LE(0, 26); // survey id
    response.writeUInt16LE(0, 30); // unk

    socket.write(response);
    console.log("Sent logon proof response - authentication successful!");
  }

  private sha1Interleave(S: Buffer): Buffer {
    // Split S into two buffers (even and odd indices)
    const buf0 = Buffer.alloc(16);
    const buf1 = Buffer.alloc(16);

    for (let i = 0; i < 16; i++) {
      buf0[i] = S[i * 2];
      buf1[i] = S[i * 2 + 1];
    }

    // Find position of first nonzero byte in S
    let p = 0;
    while (p < 32 && S[p] === 0) {
      p++;
    }

    // Skip one extra byte if p is odd
    if (p & 1) {
      p++;
    }

    p = Math.floor(p / 2); // offset into buffers

    // Hash each half starting at first nonzero position
    const hash0 = crypto.createHash("sha1").update(buf0.slice(p)).digest();
    const hash1 = crypto.createHash("sha1").update(buf1.slice(p)).digest();

    // Interleave the two hashes back together
    const K = Buffer.alloc(40);
    for (let i = 0; i < 20; i++) {
      K[i * 2] = hash0[i];
      K[i * 2 + 1] = hash1[i];
    }

    return K;
  }

  private async handleRealmList(socket: net.Socket) {
    console.log("Realm list requested");

    // Query realms from database
    const [rows] = await this.db!.execute(
      "SELECT id, name, address, port, icon, realmflags, timezone, population FROM realmlist WHERE flag <> 3 ORDER BY name"
    );

    const realms = rows as any[];

    // Build realm list packet
    const realmData: Buffer[] = [];
    let totalSize = 8; // header size

    for (const realm of realms) {
      const nameBuffer = Buffer.from(realm.name + "\0", "utf8");
      const addressBuffer = Buffer.from(
        `${realm.address}:${realm.port}\0`,
        "utf8"
      );

      const realmBuffer = Buffer.alloc(
        9 + nameBuffer.length + addressBuffer.length
      );
      let offset = 0;

      realmBuffer.writeUInt8(realm.icon, offset++);
      realmBuffer.writeUInt8(0, offset++); // locked
      realmBuffer.writeUInt8(realm.realmflags, offset++);
      nameBuffer.copy(realmBuffer, offset);
      offset += nameBuffer.length;
      addressBuffer.copy(realmBuffer, offset);
      offset += addressBuffer.length;
      realmBuffer.writeFloatLE(realm.population, offset);
      offset += 4;
      realmBuffer.writeUInt8(0, offset++); // num chars
      realmBuffer.writeUInt8(realm.timezone, offset++);
      realmBuffer.writeUInt8(0, offset); // realm id

      realmData.push(realmBuffer);
      totalSize += realmBuffer.length;
    }

    // Build final packet
    const response = Buffer.alloc(totalSize);
    let offset = 0;
    response.writeUInt8(AuthCmd.REALM_LIST, offset++);
    response.writeUInt16LE(totalSize - 3, offset);
    offset += 2;
    response.writeUInt32LE(0, offset);
    offset += 4; // unknown
    response.writeUInt16LE(realms.length, offset);
    offset += 2;

    for (const realmBuffer of realmData) {
      realmBuffer.copy(response, offset);
      offset += realmBuffer.length;
    }

    response.writeUInt8(0x10, offset++); // unused
    response.writeUInt8(0x00, offset); // unused

    socket.write(response);
    console.log(`Sent realm list with ${realms.length} realm(s)`);
  }

  private modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
      if (exp % BigInt(2) === BigInt(1)) result = (result * base) % mod;
      exp = exp / BigInt(2);
      base = (base * base) % mod;
    }
    return result;
  }

  private bigIntToBuffer(num: bigint, size: number): Buffer {
    const hex = num.toString(16).padStart(size * 2, "0");
    return Buffer.from(hex, "hex");
  }
}

// Account creation function
async function createAccount(
  username: string,
  password: string,
  email: string = "",
  expansion: number = 2
) {
  const db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "auth",
  });

  try {
    // Check if account already exists
    const [existing] = await db.execute(
      "SELECT id FROM account WHERE username = ?",
      [username.toUpperCase()]
    );

    if (Array.isArray(existing) && existing.length > 0) {
      console.log(`Account '${username}' already exists!`);
      await db.end();
      return false;
    }

    // Generate salt and verifier
    const salt = SRP6.generateSalt();
    const verifier = SRP6.calculateVerifier(username, password, salt);

    // AzerothCore expects these values reversed and in hex
    const saltHex = salt.reverse().toString("hex").toUpperCase();
    const verifierHex = verifier.reverse().toString("hex").toUpperCase();

    // Insert new account
    await db.execute(
      `INSERT INTO account (username, salt, verifier, email, expansion, joindate) 
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [username.toUpperCase(), saltHex, verifierHex, email, expansion]
    );

    console.log(`Account '${username}' created successfully!`);
    console.log(`Email: ${email || "none"}`);
    console.log(`Expansion: ${expansion} (0=Classic, 1=TBC, 2=WotLK)`);

    await db.end();
    return true;
  } catch (error) {
    console.error("Error creating account:", error);
    await db.end();
    return false;
  }
}

// Configuration
const authServer = new AuthServer(3724, {
  host: "localhost",
  user: "root",
  password: "",
  database: "auth",
});

authServer.start().catch(console.error);

// Example: Create a new account (uncomment to use)
//createAccount("testuser", "testpass", "test@example.com", 2)

import { AuthHelper, AuthResult } from "../authentication/auth-codes";
import { sAuthSocketMgr } from "./auth-socket-mgr";
import { AccountTypes } from "../../../../common/common";
import { Packet } from "./packet";
import { Logger } from "../../../../tools/logger";
import { LoginDatabase } from "../../../database/database/login-database";
import { Socket } from "./socket";
import { sAccountMgr } from "../../../../server/game/accounts/account-mgr";
import { SRP6 } from "../../../../common/cryptography/authentication/srp6";
import { bigintToBuf, bufToBigint } from "bigint-conversion";

export enum eAuthCmd {
  AUTH_LOGON_CHALLENGE = 0x00,
  AUTH_LOGON_PROOF = 0x01,
  AUTH_RECONNECT_CHALLENGE = 0x02,
  AUTH_RECONNECT_PROOF = 0x03,
  REALM_LIST = 0x10,
  XFER_INITIATE = 0x30,
  XFER_DATA = 0x31,
  XFER_ACCEPT = 0x32,
  XFER_RESUME = 0x33,
  XFER_CANCEL = 0x34,
}

export enum AuthStatus {
  STATUS_CHALLENGE,
  STATUS_LOGON_PROOF,
  STATUS_RECONNECT_PROOF,
  STATUS_AUTHED,
  STATUS_WAITING_FOR_REALM_LIST,
  STATUS_CLOSED,
}
const VersionChallenge: Buffer = Buffer.from([
  0xba, 0xa3, 0x1e, 0x99, 0xa0, 0x0b, 0x21, 0x57, 0xfc, 0x37, 0x3f, 0xb3, 0x69,
  0xcd, 0xd2, 0xf1,
]);
export const AUTH_LOGON_CHALLENGE_INITIAL_SIZE = 4;
export const REALM_LIST_PACKET_SIZE = 5;

type LOGIN_SEL_LOGONCHALLENGE = Awaited<
  ReturnType<typeof LoginDatabase.LOGIN_SEL_LOGONCHALLENGE>
>;

export class AccountInfo {
  public id: number = 0;
  public Login: string = "";
  public IsLockedToIP: boolean = false;
  public lockCountry: string = "";
  public LastIP: string = "";
  public failedLogins: number = 0;
  public IsBanned: boolean = false;
  public IsPermanentlyBanned: boolean = false;
  public securityLevel: AccountTypes = AccountTypes.SEC_PLAYER;

  LoadResult(fields: NonNullable<LOGIN_SEL_LOGONCHALLENGE>): void {
    this.id = fields.id;
    this.Login = fields.username;
    this.IsLockedToIP = Boolean(fields.locked);
    this.lockCountry = fields.lock_country;
    this.failedLogins = fields.failed_logins;
    this.LastIP = fields.last_ip;
    this.IsBanned = fields.is_account_banned || fields.is_ip_banned;
    this.IsPermanentlyBanned = fields.ip_unbandate || fields.account_unbandate;
    this.securityLevel =
      fields.gmlevel! > AccountTypes.SEC_CONSOLE
        ? AccountTypes.SEC_CONSOLE
        : fields.gmlevel!;
    // no implementation
  }
}

export class AuthSession extends Socket<AuthSession> {
  private _srp6?: SRP6;
  private _sessionKey = {};
  private _status: AuthStatus = AuthStatus.STATUS_CHALLENGE;
  private _accountInfo = new AccountInfo();
  private _totpSecret?: Buffer;
  private _localizationName = "";
  private _os = "";
  private _ipCountry = "";
  private _build: number = 0;
  private _expversion: number = 0;
  private _version: string = "0.0.0";
  private _platform: string = "";

  protected OnOpcode(opcode: eAuthCmd) {
    switch (opcode) {
      case eAuthCmd.AUTH_LOGON_CHALLENGE:
        console.log("LOGON CHALLENGE CALLED FROM CLIENT");
        this.#HandleLogonChallenge();
        break;
      case eAuthCmd.AUTH_LOGON_PROOF:
        console.log("LOGON PROOF CALLED FROM CLIENT");
        this.#HandleLogonProof();
        break;
      case eAuthCmd.AUTH_RECONNECT_CHALLENGE:
        this.#HandleReconnectChallenge();
        break;
      case eAuthCmd.AUTH_RECONNECT_PROOF:
        this.#HandleReconnectProof();
        break;
      case eAuthCmd.REALM_LIST:
        console.log("REALM LIST CALLED FROM CLIENT");
        this.#HandleRealmList();
        break;
      default:
        break;
    }
  }
  protected OnDisconnect() {
    super.OnDisconnect();
    sAuthSocketMgr.RemoveSession(this.socket);
    Logger.info(`[AUTH] Client disconnected: ${this.GetRemoteIpAddress()}`);
  }
  protected OnError(error: Error): void {
    if (error.message.includes("ECONNRESET")) {
      Logger.warn("[AUTH] Client connection reset:", this.GetRemoteAddress());
    } else {
      Logger.error(
        `[AUTH] Socket error from ${this.GetRemoteAddress()}:`,
        error.message
      );
    }
  }

  async #HandleLogonChallenge() {
    this._status = AuthStatus.STATUS_CLOSED;
    const data = this.GetReadBuffer();
    if (data.length < 34) return null;

    const cmd = data.readUInt8(0);
    if (cmd !== 0x00) return null;

    const username = parseUsername(data, 34, data.readUInt8(33));
    Logger.info(`[AuthChallenge] '${username}'`);

    this._expversion = data.readUInt8(8);
    this._version = `${this._expversion}.${data.readUInt8(9)}.${data.readUInt8(
      10
    )}`;
    this._build = data.readUInt16LE(11);
    this._platform = parseReversedString(data, 13, 17);
    this._os = parseReversedString(data, 17, 21);
    this._localizationName = parseReversedString(data, 21, 25);

    const result = await LoginDatabase.LOGIN_SEL_LOGONCHALLENGE(
      parseIpString(data, 29, 33),
      username
    );

    console.log({ result });
    this.#LogonChallengeCallback(result);

    return true;
  }
  async #LogonChallengeCallback(result: LOGIN_SEL_LOGONCHALLENGE) {
    const pkt = new Packet().uint8(eAuthCmd.AUTH_LOGON_CHALLENGE).uint8(0x00);

    if (!result) {
      pkt.uint8(AuthResult.WOW_FAIL_UNKNOWN_ACCOUNT);
      this.SendPacket(pkt);
      return;
    }
    this._accountInfo.LoadResult(result);

    const ipAddress = this.GetRemoteIpAddress();
    const port = this.GetRemotePort();

    if (this._accountInfo.IsLockedToIP) {
      Logger.info(
        `[AuthChallenge] Account '${this._accountInfo.Login}' is locked to IP - '${this._accountInfo.LastIP}' is logging in from '${ipAddress}'`
      );
      if (this._accountInfo.LastIP != ipAddress) {
        pkt.uint8(AuthResult.WOW_FAIL_LOCKED_ENFORCED);
        this.SendPacket(pkt);
        return;
      }
    } else {
      //
    }

    if (this._accountInfo.IsBanned) {
      if (this._accountInfo.IsPermanentlyBanned) {
        pkt.uint8(AuthResult.WOW_FAIL_BANNED);
        this.SendPacket(pkt);
        Logger.info(
          `'${ipAddress}:${port}' [AuthChallenge] Banned account ${this._accountInfo.Login} tried to login!`
        );
        return;
      } else {
        pkt.uint8(AuthResult.WOW_FAIL_SUSPENDED);
        this.SendPacket(pkt);
        Logger.info(
          `'${ipAddress}:${port}' [AuthChallenge] Temporarily banned account ${this._accountInfo.Login} tried to login!`
        );
        return;
      }
    }

    let securityFlags = 0;

    if (typeof result.totp_secret === "string") {
      securityFlags = 4;
      this._totpSecret = Buffer.from(result.totp_secret);
      const secret = ""; //sSecretMgr.GetSecret(SECRET_TOTP_MASTER_KEY)

      if (secret) {
        const success = true; // check AEDecrypt
        if (!success) {
          pkt.uint8(AuthResult.WOW_FAIL_DB_BUSY);
          this.SendPacket(pkt);
          return;
        }
      }
    }

    this._srp6 = new SRP6(
      this._accountInfo.Login,
      result.salt, //salt
      result.verifier //verifier
    );

    if (AuthHelper.IsPostBCAcceptedClientBuild(this._build)) {
      pkt
        .uint8(AuthResult.WOW_SUCCESS)
        .append(this._srp6.B)
        .uint8(1)
        .append(SRP6.g)
        .uint8(32)
        .append(SRP6.N)
        .append(this._srp6.s)
        .append(VersionChallenge)
        //.append(Buffer.from([VersionChallenge.length]))
        .uint8(securityFlags);

      if (securityFlags & 0x01) {
        pkt.uint32(0).uint64(0).uint64(0);
      }
      if (securityFlags & 0x02) {
        pkt.uint8(0).uint8(0).uint8(0).uint8(0).uint64(0);
      }
      if (securityFlags & 0x04) pkt.uint8(1);

      Logger.info(
        `'${ipAddress}:${port}' [AuthChallenge] account ${
          this._accountInfo.Login
        } is using '${this._localizationName}' locale (${"RO"})`
      );

      this._status = AuthStatus.STATUS_LOGON_PROOF;
    } else pkt.uint8(AuthResult.WOW_FAIL_VERSION_INVALID);

    this.SendPacket(pkt);
    //console.log(`[AUTH] ${info?.username} is logging in.`);
  }
  async #HandleLogonProof() {
    this._status = AuthStatus.STATUS_CLOSED;
    const data = this.GetReadBuffer();

    // Packet Validation
    if (data.length < 75) {
      Logger.warn(`[Auth] Malformed LogonProof packet. Length: ${data.length}`);
      return;
    }
    // 1. Read 'A' (Client Public Key) - 32 Bytes
    const A = data.subarray(1, 33);

    const a = bufToBigint(A);

    // 2. Read Client Proof (M1) - 20 Bytes
    // M1 is a SHA1 hash, which is a byte stream. DO NOT REVERSE THIS.
    const clientM = data.subarray(33, 53);

    // 3. Read CRC Hash - 20 Bytes
    const crcHash = data.subarray(53, 73);

    // 4. Check SRP6 Initialization
    if (!this._srp6) {
      Logger.error(
        "[Auth] SRP6 not initialized. Client skipped Challenge step?"
      );
      this.#SendProofError(AuthResult.WOW_FAIL_UNKNOWN_ACCOUNT);
      return;
    }

    // 5. Verify
    // We pass the Big-Endian 'A' and the standard 'clientM'
    const sessionKey = this._srp6.VerifyChallengeResponse(A, clientM);

    if (sessionKey) {
      // --- SUCCESS ---
      this._sessionKey = sessionKey;
      Logger.info(
        `[Auth] User '${this._accountInfo.Login}' Authenticated successfully.`
      );

      // Update DB stats here (Login time, IP, SessionKey)...

      // Calculate Server Proof M2
      // Note: GetSessionVerifier expects 'A' in the format used for hashing.
      // In standard WoW SRP6, M2 = H(A, M, K). 'A' is hashed as Little Endian (rawA).
      const M2 = SRP6.GetSessionVerifier(A, clientM, sessionKey);

      const pkt = new Packet().uint8(eAuthCmd.AUTH_LOGON_PROOF);
      pkt.uint8(AuthResult.WOW_SUCCESS);
      pkt.append(M2); // 20 bytes
      pkt.uint32(0x00800000); // AccountFlags
      pkt.uint32(0); // SurveyId
      pkt.uint16(0); // LoginFlags

      this.SendPacket(pkt);
      this._status = AuthStatus.STATUS_AUTHED;
    } else {
      // --- FAILURE ---
      Logger.warn(
        `[Auth] User '${this._accountInfo.Login}' failed authentication (Wrong Password).`
      );
      this.#SendProofError(AuthResult.WOW_FAIL_INCORRECT_PASSWORD);
    }
  }
  async #HandleReconnectChallenge() {
    //
  }
  async #ReconnectChallengeCallback() {
    //
  }
  async #HandleReconnectProof() {
    //
  }
  async #HandleRealmList() {
    const result = await LoginDatabase.LOGIN_SEL_REALM_CHARACTER_COUNTS(
      this._accountInfo.id
    );
    this.RealmListCallback(result);
    this._status = AuthStatus.STATUS_WAITING_FOR_REALM_LIST;
    return true;
  }
  private RealmListCallback(
    result: Awaited<
      ReturnType<typeof LoginDatabase.LOGIN_SEL_REALM_CHARACTER_COUNTS>
    >
  ) {
    //
  }

  #SendProofError(error: AuthResult) {
    const pkt = new Packet()
      .uint8(eAuthCmd.AUTH_LOGON_PROOF)
      .uint8(error)
      .uint16(0);
    this.SendPacket(pkt);
  }
}

function parseReversedString(buffer: Buffer, start: number, end: number) {
  return buffer
    .subarray(start, end)
    .reverse()
    .toString("ascii")
    .replace(/\0/g, "");
}

function parseIpString(buffer: Buffer, start: number, end: number) {
  return Array.from(buffer.subarray(start, end)).join(".");
}

function parseUsername(buffer: Buffer, start: number, length: number) {
  return buffer.toString("utf8", start, start + length);
}
export function reverseBuffer(buf: Buffer): Buffer {
  const reversed = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    reversed[i] = buf[buf.length - 1 - i];
  }
  return reversed;
}

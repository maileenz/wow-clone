import { Singletons } from "../../../common/utilities/singletons";
import { AccountTypes } from "../../../common/common";
import { authDb } from "../../../server/database/auth";
import { account } from "../../../server/database/auth/schema";
import { LoginDatabase } from "../../../server/database/database/login-database";
import { eq } from "drizzle-orm";
import { SRP6 } from "../../../common/cryptography/authentication/srp6";

export enum AccountOpResult {
  AOR_OK,
  AOR_NAME_TOO_LONG,
  AOR_PASS_TOO_LONG,
  AOR_EMAIL_TOO_LONG,
  AOR_NAME_ALREADY_EXIST,
  AOR_NAME_NOT_EXIST,
  AOR_DB_INTERNAL_ERROR,
}

const MAX_ACCOUNT_STR = 17;
const MAX_PASS_STR = 16;
const MAX_EMAIL_STR = 255;

export class AccountMgr {
  async CreateAccount(
    username: string,
    password: string,
    email = ""
  ): Promise<AccountOpResult> {
    if (utf8Length(username) > MAX_ACCOUNT_STR)
      return AccountOpResult.AOR_NAME_TOO_LONG;
    if (utf8Length(password) > MAX_PASS_STR)
      return AccountOpResult.AOR_PASS_TOO_LONG;
    if (utf8Length(email) > MAX_EMAIL_STR)
      return AccountOpResult.AOR_EMAIL_TOO_LONG;

    username = username.toUpperCase();
    password = password.toUpperCase();
    email = email.toUpperCase();

    if (await this.GetId(username))
      return AccountOpResult.AOR_NAME_ALREADY_EXIST;

    try {
      const [salt, verifier] = SRP6.MakeRegistrationData(username, password);
      await LoginDatabase.LOGIN_INS_ACCOUNT(username, salt, verifier, 2, email);
      await LoginDatabase.LOGIN_INS_REALM_CHARACTERS_INIT();

      return AccountOpResult.AOR_OK;
    } catch (err) {
      console.error("Account creation failed:", err);
      return AccountOpResult.AOR_DB_INTERNAL_ERROR;
    }
  }
  async GetId(username: string): Promise<number | undefined> {
    const result = await authDb
      .select({ id: account.id })
      .from(account)
      .where(eq(account.username, username));
    return result.pop()?.id;
  }
  IsPlayerAccount(gmlevel: number): boolean {
    return gmlevel === AccountTypes.SEC_PLAYER;
  }
  IsGMAccount(gmlevel: number): boolean {
    return gmlevel >= AccountTypes.SEC_GAMEMASTER;
  }
  IsAdminAccount(gmlevel: number): boolean {
    return (
      gmlevel >= AccountTypes.SEC_ADMINISTRATOR &&
      gmlevel <= AccountTypes.SEC_CONSOLE
    );
  }
  IsConsoleAccount(gmlevel: number): boolean {
    return gmlevel === AccountTypes.SEC_CONSOLE;
  }
}

export const sAccountMgr = Singletons.create(AccountMgr);

function utf8Length(str: string): number {
  return encodeURIComponent(str).replace(/%[A-F\d]{2}/g, "A").length;
}

function utf8ToUpperOnlyLatin(str: string): string {
  return str.toUpperCase(); // Simplified — real impl should preserve non-latin chars
}

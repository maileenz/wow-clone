import { and, eq, or, sql } from "drizzle-orm";
import {
  account,
  accountAccess,
  accountBanned,
  ipBanned,
  realmCharacters,
} from "../auth/schema";
import { authDb } from "../auth";
import crypto from "crypto";

export class LoginDatabase {
  public static async LOGIN_SEL_LOGON(username: string) {
    const result = await authDb.execute(
      [
        "SELECT a.id, a.username, a.locked, a.lock_country, a.last_ip, a.failed_logins, ",
        "ab.unbandate > UNIX_TIMESTAMP() OR ab.unbandate = ab.bandate, ab.unbandate = ab.bandate, ",
        "ipb.unbandate > UNIX_TIMESTAMP() OR ipb.unbandate = ipb.bandate, ipb.unbandate = ipb.bandate, ",
        "aa.gmlevel, a.totp_secret, a.salt, a.verifier ",
        "FROM account a ",
        "LEFT JOIN account_access aa ON a.id = aa.id ",
        "LEFT JOIN account_banned ab ON ab.id = a.id AND ab.active = 1 ",
        "LEFT JOIN ip_banned ipb ON ipb.ip = '127.0.0.1' ",
        `WHERE a.username = '${username}'`,
      ].join("")
    );
    console.log({ result: result[0] });
  }
  public static async LOGIN_SEL_LOGONCHALLENGE(
    clientIp: string,
    username: string
  ) {
    const accountBanActiveCheck = or(
      // Ban is active if unban date is in the future
      sql<boolean>`${accountBanned.unbandate} > UNIX_TIMESTAMP()`,
      // OR ban is permanent (unbandate equals bandate)
      sql<boolean>`${accountBanned.unbandate} = ${accountBanned.bandate}`
    );

    const ipBanActiveCheck = or(
      // Ban is active if unban date is in the future
      sql<boolean>`${ipBanned.unbandate} > UNIX_TIMESTAMP()`,
      // OR ban is permanent (unbandate equals bandate)
      sql<boolean>`${ipBanned.unbandate} = ${ipBanned.bandate}`
    );

    let result;
    result = await authDb
      .select({
        id: account.id,
        username: account.username,
        locked: account.locked,
        lock_country: account.lock_country,
        last_ip: account.last_ip,
        failed_logins: account.failed_logins,

        // Fields 6 & 7: Account Ban Status/Expiry Check
        is_account_banned: sql<boolean>`${accountBanActiveCheck}`.as(
          "is_account_banned"
        ),
        account_unbandate:
          sql<boolean>`${accountBanned.unbandate} = ${accountBanned.bandate}`.as(
            "account_unbandate"
          ),

        // Fields 8 & 9: IP Ban Status/Expiry Check
        is_ip_banned: sql<boolean>`${ipBanActiveCheck}`.as("is_ip_banned"),
        ip_unbandate:
          sql<boolean>`${ipBanned.unbandate} = ${ipBanned.bandate}`.as(
            "ip_unbandate"
          ),

        // Field 10: GM Level
        gmlevel: accountAccess.gmlevel,
        totp_secret: account.totp_secret,
        salt: account.salt,
        verifier: account.verifier,
      })
      .from(account)
      // LEFT JOIN account_access aa ON a.id = aa.id
      .leftJoin(accountAccess, eq(account.id, accountAccess.id))

      // LEFT JOIN account_banned ab ON ab.id = a.id AND ab.active = 1
      .leftJoin(
        accountBanned,
        and(eq(accountBanned.id, account.id), eq(accountBanned.active, 1))
      )

      // LEFT JOIN ip_banned ipb ON ipb.ip = ? (clientIp)
      // NOTE: Drizzle requires a table reference (like the account table) in the ON clause,
      // so we must use a constant value check here.
      .leftJoin(ipBanned, eq(ipBanned.ip, clientIp))

      // WHERE a.username = ? (username)
      .where(eq(account.username, username));

    return result.pop();
  }

  public static LOGIN_SEL_REALM_CHARACTER_COUNTS(accountId: number) {
    return authDb
      .select({
        realmid: realmCharacters.realmid,
        numchars: realmCharacters.numchars,
      })
      .from(realmCharacters)
      .where(eq(realmCharacters.acctid, accountId));
  }

  public static async LOGIN_INS_ACCOUNT(
    username: string,
    salt: string,
    verifier: string,
    expansion = 2,
    email = ""
  ) {
    await authDb.insert(account).values({
      username,
      salt,
      verifier,
      expansion,
      email,
      reg_mail: email,
      joindate: new Date(),
    });
  }

  public static async LOGIN_INS_REALM_CHARACTERS_INIT() {
    await authDb.execute(`
      INSERT INTO realmcharacters (realmid, acctid, numchars)
      SELECT realmlist.id, account.id, 0
      FROM realmlist, account
      LEFT JOIN realmcharacters ON acctid = account.id
      WHERE acctid IS NULL
    `);
  }
}

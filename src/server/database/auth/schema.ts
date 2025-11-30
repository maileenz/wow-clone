import { mysqlTableCreator, primaryKey } from "drizzle-orm/mysql-core";
/**
 * This is an example of how to use the multi-project schema feature of Drizzle ORM. Use the same
 * database instance for multiple projects.
 *
 * @see https://orm.drizzle.team/docs/goodies#multi-project-schema
 */
export const createTable = mysqlTableCreator((name) => name);

export const test = createTable("test", (d) => ({
  id: d.int({ unsigned: true }).notNull().primaryKey().autoincrement(),
  salt: d.varchar({ length: 64 }).notNull(),
}));

export const account = createTable("account", (d) => ({
  id: d.int({ unsigned: true }).notNull().primaryKey().autoincrement(),

  username: d.varchar({ length: 32 }).notNull().unique().default(""),

  salt: d.varchar({ length: 64 }).notNull(),

  verifier: d.varchar({ length: 64 }).notNull(),

  session_key: d.binary({ length: 40 }), // Nullable

  totp_secret: d.varbinary({ length: 100 }), // Nullable

  email: d.varchar({ length: 255 }).notNull().default(""),

  reg_mail: d.varchar({ length: 255 }).notNull().default(""),

  joindate: d.timestamp().notNull().defaultNow(),

  last_ip: d.varchar({ length: 15 }).notNull().default("127.0.0.1"),

  last_attempt_ip: d.varchar({ length: 15 }).notNull().default("127.0.0.1"),

  failed_logins: d.int({ unsigned: true }).notNull().default(0),

  locked: d.tinyint({ unsigned: true }).notNull().default(0),

  lock_country: d.varchar({ length: 2 }).notNull().default("00"),

  last_login: d.timestamp().default(new Date()), // Nullable

  online: d.int({ unsigned: true }).notNull().default(0),

  expansion: d.tinyint({ unsigned: true }).notNull().default(2),

  Flags: d.int({ unsigned: true }).notNull().default(0),

  mutetime: d.bigint({ mode: "number" }).notNull().default(0),

  mutereason: d.varchar({ length: 255 }).notNull().default(""),

  muteby: d.varchar({ length: 50 }).notNull().default(""),

  locale: d.tinyint({ unsigned: true }).notNull().default(0),

  os: d.varchar({ length: 3 }).notNull().default(""),

  recruiter: d.int({ unsigned: true }).notNull().default(0),

  totaltime: d.int({ unsigned: true }).notNull().default(0),
}));

export const accountAccess = createTable(
  "account_access",
  (d) => ({
    // id: INT UNSIGNED, part of the composite primary key
    id: d.int({ unsigned: true }).notNull(),

    // gmlevel: TINYINT UNSIGNED
    gmlevel: d.tinyint({ unsigned: true }).notNull(),

    // RealmID: INT SIGNED, part of the composite primary key, Default -1
    RealmID: d.int().notNull().default(-1),

    // comment: VARCHAR(255), Nullable, Default ''
    comment: d.varchar({ length: 255 }).default(""), // Nullable by default
  }),
  (t) => [
    // Define the composite primary key constraint
    primaryKey({ columns: [t.id, t.RealmID] }),
  ]
);

export const accountBanned = createTable(
  "account_banned",
  (d) => ({
    // id: INT UNSIGNED, Primary Key (Part 1), Default 0. Links to account.id
    id: d.int("id", { unsigned: true }).notNull().default(0),

    // bandate: INT UNSIGNED, Primary Key (Part 2), Default 0. (This is a Unix timestamp)
    bandate: d.int("bandate", { unsigned: true }).notNull().default(0),

    // unbandate: INT UNSIGNED, Default 0. (The expiration time, 0 if permanent)
    unbandate: d.int("unbandate", { unsigned: true }).notNull().default(0),

    // bannedby: VARCHAR(50)
    bannedby: d.varchar("bannedby", { length: 50 }).notNull(),

    // banreason: VARCHAR(255)
    banreason: d.varchar("banreason", { length: 255 }).notNull(),

    // active: TINYINT UNSIGNED, Default 1 (1 = active ban, 0 = expired/removed)
    active: d.tinyint("active", { unsigned: true }).notNull().default(1),
  }),
  (t) => [
    // Define the composite primary key on id and bandate
    primaryKey({ columns: [t.id, t.bandate] }),
  ]
);

export const ipBanned = createTable(
  "ip_banned",
  (d) => ({
    // ip: VARCHAR(15), Primary Key (Part 1), Default 127.0.0.1
    ip: d.varchar("ip", { length: 15 }).notNull().default("127.0.0.1"),

    // bandate: INT UNSIGNED, Primary Key (Part 2). (This is a Unix timestamp)
    bandate: d.int("bandate", { unsigned: true }).notNull(),

    // unbandate: INT UNSIGNED. (The expiration time)
    unbandate: d.int("unbandate", { unsigned: true }).notNull(),

    // bannedby: VARCHAR(50), Default [Console]
    bannedby: d
      .varchar("bannedby", { length: 50 })
      .notNull()
      .default("[Console]"),

    // banreason: VARCHAR(255), Default no reason
    banreason: d
      .varchar("banreason", { length: 255 })
      .notNull()
      .default("no reason"),
  }),
  (t) => [
    // Define the composite primary key on ip and bandate
    primaryKey({ columns: [t.ip, t.bandate] }),
  ]
);

export const realmCharacters = createTable(
  "realmcharacters",
  (d) => ({
    // realmid: INT UNSIGNED, Primary Key (Part 1), Default 0
    realmid: d.int("realmid", { unsigned: true }).notNull().default(0),

    // acctid: INT UNSIGNED, Primary Key (Part 2). (Links to account.id)
    acctid: d.int("acctid", { unsigned: true }).notNull(),

    // numchars: TINYINT UNSIGNED, Default 0.
    numchars: d.tinyint("numchars", { unsigned: true }).notNull().default(0),
  }),
  (t) => [
    // Define the composite primary key on realmid and acctid
    primaryKey({ columns: [t.realmid, t.acctid] }),
  ]
);

export const realmlist = createTable(
  "realmlist",
  (d) => ({
    // id: INT UNSIGNED, Primary Key, Auto Increment
    id: d.int("id", { unsigned: true }).notNull().primaryKey().autoincrement(),

    // name: VARCHAR(32), Unique, Default ''
    name: d.varchar("name", { length: 32 }).notNull().unique().default(""),

    // address: VARCHAR(255), Default 127.0.0.1
    address: d
      .varchar("address", { length: 255 })
      .notNull()
      .default("127.0.0.1"),

    // localAddress: VARCHAR(255), Default 127.0.0.1
    localAddress: d
      .varchar("localAddress", { length: 255 })
      .notNull()
      .default("127.0.0.1"),

    // localSubnetMask: VARCHAR(255), Default 255.255.255.0
    localSubnetMask: d
      .varchar("localSubnetMask", { length: 255 })
      .notNull()
      .default("255.255.255.0"),

    // port: SMALLINT UNSIGNED, Default 8085
    port: d.smallint("port", { unsigned: true }).notNull().default(8085),

    // icon: TINYINT UNSIGNED, Default 0
    icon: d.tinyint("icon", { unsigned: true }).notNull().default(0),

    // flag: TINYINT UNSIGNED, Default 2
    flag: d.tinyint("flag", { unsigned: true }).notNull().default(2),

    // timezone: TINYINT UNSIGNED, Default 0
    timezone: d.tinyint("timezone", { unsigned: true }).notNull().default(0),

    // allowedSecurityLevel: TINYINT UNSIGNED, Default 0
    allowedSecurityLevel: d
      .tinyint("allowedSecurityLevel", { unsigned: true })
      .notNull()
      .default(0),

    // population: FLOAT, Default 0
    population: d.float("population").notNull().default(0),

    // gamebuild: INT UNSIGNED, Default 12340
    gamebuild: d.int("gamebuild", { unsigned: true }).notNull().default(12340),
  }),
  (t) => [
    // Constraints section (empty for this table, as PK is defined inline and name is unique)
  ]
);

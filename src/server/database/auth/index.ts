import { drizzle } from "drizzle-orm/mysql2";
import { createPool, type Pool } from "mysql2/promise";

import { env } from "../../../env";
import * as schema from "./schema";
import { and, eq, or, sql } from "drizzle-orm";

/**
 * Cache the database connection in development. This avoids creating a new connection on every HMR
 * update.
 */
const globalForDb = globalThis as unknown as {
  conn: Pool | undefined;
};

const conn =
  globalForDb.conn ??
  createPool({
    uri: env.DATABASE_URL,
    supportBigNumbers: true,
    bigNumberStrings: false,
    dateStrings: false,
    typeCast: (field, next) => {
      if (
        field.type === "BLOB" ||
        // @ts-ignore
        field.type === "BINARY" ||
        // @ts-ignore
        field.type === "VARBINARY"
      ) {
        return field.buffer();
      }
      return next();
    },
  });
if (env.NODE_ENV !== "production") globalForDb.conn = conn;

export const authDb = drizzle(conn, { schema, mode: "default" });

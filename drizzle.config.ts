import { type Config } from "drizzle-kit";

import { env } from "./src/env";

export default {
  schema: "./src/server/database/auth/schema.ts",
  dialect: "mysql",
  dbCredentials: {
    url: env.DATABASE_URL,
  },
  //tablesFilter: ["next-mmo_*"],
} satisfies Config;

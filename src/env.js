import "dotenv/config";
import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";

export const env = createEnv({
  /**
   * Specify your server-side environment variables schema here. This way you can ensure the app
   * isn't built with invalid env vars.
   */
  server: {
    AUTH_SERVER_HOST: z.ipv4(),
    AUTH_SERVER_PORT: z.number(),
    WORLD_SERVER_HOST: z.ipv4(),
    WORLD_SERVER_PORT: z.number(),
    DATABASE_URL: z.url(),
    IPLocationFile: z.string(),
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
  },

  /**
   * Specify your client-side environment variables schema here. This way you can ensure the app
   * isn't built with invalid env vars. To expose them to the client, prefix them with
   * `NEXT_PUBLIC_`.
   */
  client: {
    // NEXT_PUBLIC_CLIENTVAR: z.string(),
  },

  /**
   * You can't destruct `process.env` as a regular object in the Next.js edge runtimes (e.g.
   * middlewares) or client-side so we need to destruct manually.
   */
  runtimeEnv: {
    AUTH_SERVER_HOST: process.env.AUTH_SERVER_HOST,
    AUTH_SERVER_PORT: Number(process.env.AUTH_SERVER_PORT),
    WORLD_SERVER_HOST: process.env.WORLD_SERVER_HOST,
    WORLD_SERVER_PORT: Number(process.env.WORLD_SERVER_PORT),
    IPLocationFile: process.env.IPLocationFile,
    DATABASE_URL: process.env.DATABASE_URL,
    NODE_ENV: process.env.NODE_ENV,
  },
  /**
   * Run `build` or `dev` with `SKIP_ENV_VALIDATION` to skip env validation. This is especially
   * useful for Docker builds.
   */
  skipValidation: !!process.env.SKIP_ENV_VALIDATION,
  /**
   * Makes it so that empty strings are treated as undefined. `SOME_VAR: z.string()` and
   * `SOME_VAR=''` will throw an error.
   */
  emptyStringAsUndefined: true,
});

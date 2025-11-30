import { compare, genSalt, hash } from "bcrypt";

export async function generateCredentials(password: string) {
  const salt = await genSalt();
  const verifier = await hash(password, salt);
  return { salt, verifier };
}

export function checkCredentials(password: string, verifier: string) {
  return compare(password, verifier);
}

export function ASSERT(condition: boolean, message: string) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

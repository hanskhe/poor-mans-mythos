import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export function hash(password: string) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${scryptSync(password, salt, 64).toString("hex")}`;
}

export function verify(password: string, stored: string) {
  const [salt, key] = stored.split(":");
  return timingSafeEqual(scryptSync(password, salt, 64), Buffer.from(key, "hex"));
}

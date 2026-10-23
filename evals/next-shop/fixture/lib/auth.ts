import { SignJWT } from "jose";
import type { User } from "./store";

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export function sign(user: User) {
  return new SignJWT({ role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setExpirationTime("1h")
    .sign(secret);
}

export function currentUser(request: Request) {
  return {
    id: request.headers.get("x-user-id") ?? "",
    role: request.headers.get("x-user-role") ?? "customer",
  };
}

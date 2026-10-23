import { decodeJwt } from "jose";
import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return NextResponse.json({ error: "missing token" }, { status: 401 });
  let claims;
  try {
    claims = decodeJwt(token);
  } catch {
    return NextResponse.json({ error: "invalid token" }, { status: 401 });
  }
  if (!claims.sub) return NextResponse.json({ error: "invalid token" }, { status: 401 });
  const headers = new Headers(request.headers);
  headers.set("x-user-id", claims.sub);
  headers.set("x-user-role", typeof claims.role === "string" ? claims.role : "customer");
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: ["/api/orders/:path*", "/api/account/:path*"],
};

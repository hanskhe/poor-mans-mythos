import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth";
import * as store from "@/lib/store";

export async function GET(request: Request) {
  const user = store.users.get(currentUser(request).id);
  if (!user) return new Response(null, { status: 404 });
  return NextResponse.json({ id: user.id, email: user.email, name: user.name, role: user.role });
}

export async function PATCH(request: Request) {
  const user = store.users.get(currentUser(request).id);
  if (!user) return new Response(null, { status: 404 });
  const body = await request.json();
  if (typeof body.name === "string") user.name = body.name.slice(0, 100);
  if (typeof body.email === "string") user.email = body.email.slice(0, 200);
  return NextResponse.json({ id: user.id, email: user.email, name: user.name, role: user.role });
}

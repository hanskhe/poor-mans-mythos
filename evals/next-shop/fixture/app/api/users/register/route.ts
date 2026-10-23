import { NextResponse } from "next/server";
import { hash } from "@/lib/passwords";
import * as store from "@/lib/store";

export async function POST(request: Request) {
  const body = await request.json();
  if (!body.email || !body.password) {
    return NextResponse.json({ error: "email and password required" }, { status: 400 });
  }
  const user = { id: store.id(), name: "", role: "customer", ...body, password: hash(body.password) };
  store.users.set(user.id, user);
  return NextResponse.json({ id: user.id }, { status: 201 });
}

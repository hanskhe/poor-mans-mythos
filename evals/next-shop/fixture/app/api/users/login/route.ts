import { NextResponse } from "next/server";
import { sign } from "@/lib/auth";
import { verify } from "@/lib/passwords";
import * as store from "@/lib/store";

export async function POST(request: Request) {
  const { email, password } = await request.json();
  const user = [...store.users.values()].find((u) => u.email === email);
  if (!user || !verify(String(password), user.password)) {
    return NextResponse.json({ error: "bad credentials" }, { status: 401 });
  }
  return NextResponse.json({ token: await sign(user) });
}

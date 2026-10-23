import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth";
import * as store from "@/lib/store";

export async function GET(request: Request) {
  const user = currentUser(request);
  const pattern = new RegExp(new URL(request.url).searchParams.get("q") ?? "", "i");
  const matches = [...store.orders.values()].filter(
    (o) => o.userId === user.id && o.items.some((item) => pattern.test(item.note ?? "")),
  );
  return NextResponse.json(matches);
}

import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth";
import * as store from "@/lib/store";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, { params }: Context) {
  const user = currentUser(request);
  const order = store.orders.get((await params).id);
  if (!order || order.userId !== user.id) return new Response(null, { status: 404 });
  return NextResponse.json(order);
}

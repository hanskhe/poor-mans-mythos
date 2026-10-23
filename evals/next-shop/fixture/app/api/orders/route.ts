import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth";
import { priceOf } from "@/lib/catalog";
import * as store from "@/lib/store";

export async function GET(request: Request) {
  const user = currentUser(request);
  return NextResponse.json([...store.orders.values()].filter((o) => o.userId === user.id));
}

export async function POST(request: Request) {
  const user = currentUser(request);
  const body = await request.json();
  const items = Array.isArray(body.items) ? body.items : [];
  const order = { id: store.id(), userId: user.id, items, status: "new" };
  store.orders.set(order.id, order);
  const total = items.reduce((sum: number, item: { sku: string }) => sum + priceOf(item.sku), 0);
  const invoice = { id: store.id(), orderId: order.id, userId: user.id, email: store.users.get(user.id)?.email ?? "", total };
  store.invoices.set(invoice.id, invoice);
  return NextResponse.json({ ...order, invoiceId: invoice.id }, { status: 201 });
}

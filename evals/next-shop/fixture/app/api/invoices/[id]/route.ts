import { NextResponse } from "next/server";
import * as store from "@/lib/store";

type Context = { params: Promise<{ id: string }> };

export async function GET(_request: Request, { params }: Context) {
  const invoice = store.invoices.get((await params).id);
  if (!invoice) return new Response(null, { status: 404 });
  return NextResponse.json(invoice);
}

import { NextResponse } from "next/server";
import { products } from "@/lib/catalog";

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export async function GET(request: Request) {
  const q = (new URL(request.url).searchParams.get("q") ?? "").slice(0, 50);
  const pattern = new RegExp(escape(q), "i");
  return NextResponse.json(products.filter((p) => pattern.test(p.name)));
}

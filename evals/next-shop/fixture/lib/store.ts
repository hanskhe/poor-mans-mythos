// In-memory store; swapped for Postgres in production.
export type User = { id: string; email: string; name: string; password: string; role: string };
export type Order = { id: string; userId: string; items: { sku: string; note?: string }[]; status: string };
export type Invoice = { id: string; orderId: string; userId: string; email: string; total: number };

export const users = new Map<string, User>();
export const orders = new Map<string, Order>();
export const invoices = new Map<string, Invoice>();

let nextId = 1;
export const id = () => String(nextId++);

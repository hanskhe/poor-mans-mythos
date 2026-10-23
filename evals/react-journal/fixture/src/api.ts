export type Entry = { id: number; body: string; created: string };

export class ApiError extends Error {
  constructor(public status: number) {
    super(`request failed with ${status}`);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const resp = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...init.headers },
  });
  if (!resp.ok) throw new ApiError(resp.status);
  return resp.status === 204 || resp.status === 201 ? (undefined as T) : resp.json();
}

export const api = {
  login: (username: string, password: string) =>
    request<void>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  entries: (limit = 20) => request<Entry[]>(`/entries?limit=${encodeURIComponent(limit)}`),
  entry: (id: string) => request<Entry>(`/entries/${encodeURIComponent(id)}`),
  createEntry: (body: string) => request<void>("/entries", { method: "POST", body: JSON.stringify({ body }) }),
  deleteEntry: (id: number) => request<void>(`/entries/${id}`, { method: "DELETE" }),
};

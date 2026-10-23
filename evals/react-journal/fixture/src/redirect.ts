// Turns a ?next= value into a same-origin path, falling back to the home page.
export function safeNext(raw: string | null): string {
  if (!raw) return "/";
  let url: URL;
  try {
    url = new URL(raw, window.location.origin);
  } catch {
    return "/";
  }
  return url.origin === window.location.origin ? url.pathname + url.search + url.hash : "/";
}

import { type FormEvent, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { api } from "../api";
import { safeNext } from "../redirect";

export default function Login() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api.login(String(form.get("username")), String(form.get("password")));
      navigate(safeNext(params.get("next")), { replace: true });
    } catch {
      setError("Wrong username or password.");
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <h1>Sign in</h1>
      <input name="username" autoComplete="username" required />
      <input name="password" type="password" autoComplete="current-password" required />
      {error && <p role="alert">{error}</p>}
      <button type="submit">Sign in</button>
    </form>
  );
}

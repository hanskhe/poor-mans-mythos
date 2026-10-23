import { type FormEvent, useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";
import { ApiError, api, type Entry } from "../api";

export default function Entries() {
  const [params] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [entries, setEntries] = useState<Entry[]>([]);
  const filter = params.get("q") ?? "";

  useEffect(() => {
    api.entries(50).then(setEntries, (err) => {
      if (err instanceof ApiError && err.status === 401) {
        navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
      }
    });
  }, [location, navigate]);

  async function onCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    await api.createEntry(String(new FormData(form).get("body")));
    form.reset();
    setEntries(await api.entries(50));
  }

  const shown = entries.filter((e) => e.body.toLowerCase().includes(filter.toLowerCase()));

  return (
    <main>
      <h1>Journal</h1>
      {filter && <p>Showing entries matching “{filter}”</p>}
      <form onSubmit={onCreate}>
        <textarea name="body" required />
        <button type="submit">Add entry</button>
      </form>
      <ul>
        {shown.map((e) => (
          <li key={e.id}>
            <Link to={`/entries/${e.id}`}>{new Date(e.created).toLocaleString()}</Link>
          </li>
        ))}
      </ul>
      <button onClick={() => api.logout().then(() => navigate("/login"))}>Sign out</button>
    </main>
  );
}

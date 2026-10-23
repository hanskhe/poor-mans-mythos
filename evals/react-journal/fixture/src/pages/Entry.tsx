import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { api, type Entry as EntryT } from "../api";
import Markdown from "../components/Markdown";
import ShareWidget from "../components/ShareWidget";

export default function Entry() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [entry, setEntry] = useState<EntryT | null>(null);

  useEffect(() => {
    api.entry(id).then(setEntry, () => navigate("/"));
  }, [id, navigate]);

  if (!entry) return null;

  return (
    <article>
      <time dateTime={entry.created}>{new Date(entry.created).toLocaleString()}</time>
      <Markdown source={entry.body} />
      <ShareWidget entryId={entry.id} />
      <button onClick={() => api.deleteEntry(entry.id).then(() => navigate("/"))}>Delete</button>
    </article>
  );
}

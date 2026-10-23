import DOMPurify from "dompurify";
import { marked } from "marked";
import { useMemo } from "react";

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") {
    node.setAttribute("target", "_blank");
    node.setAttribute("rel", "noopener noreferrer");
  }
});

export default function Markdown({ source }: { source: string }) {
  const html = useMemo(() => DOMPurify.sanitize(marked.parse(source, { async: false })), [source]);
  return <div className="markdown" dangerouslySetInnerHTML={{ __html: html }} />;
}

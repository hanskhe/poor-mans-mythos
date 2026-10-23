import { useEffect, useRef } from "react";

const WIDGET_ORIGIN = "https://share.journal-cdn.example";

export default function ShareWidget({ entryId }: { entryId: number }) {
  const frame = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== WIDGET_ORIGIN || event.source !== frame.current?.contentWindow) return;
      const height = Number(event.data?.height);
      if (frame.current && Number.isFinite(height) && height > 0 && height < 2000) {
        frame.current.style.height = `${height}px`;
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  return (
    <iframe
      ref={frame}
      title="Share"
      src={`${WIDGET_ORIGIN}/embed?entry=${encodeURIComponent(entryId)}`}
      sandbox="allow-scripts allow-same-origin allow-popups"
    />
  );
}

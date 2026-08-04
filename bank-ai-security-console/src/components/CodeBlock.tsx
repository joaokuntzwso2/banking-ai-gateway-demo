import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

interface CodeBlockProps {
  value: string;
  label?: string;
  maxHeight?: number;
}

export function CodeBlock({ value, label, maxHeight = 420 }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="code-shell">
      <div className="code-toolbar">
        <span>{label ?? 'Payload'}</span>
        <button className="icon-text-button" type="button" onClick={copy}>
          {copied ? <Check size={15} /> : <Copy size={15} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="code-block" style={{ maxHeight }}>
        <code>{value}</code>
      </pre>
    </div>
  );
}

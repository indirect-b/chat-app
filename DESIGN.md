# DESIGN.md — Chat App Visual Design System

## 1. Visual World: Nebula Minimal (Dark-First)
A precise, focused, and moody aesthetic designed for high-focus communications. The interface eliminates visual clutter, generic AI gradient slop, and oversized decoration in favor of high-contrast legibility, tactile micro-interactions, and cryptographic clarity.

- **Anchor Tone:** Deep cosmic black (`#090a0f`) and slate-toned dark surfaces (`#0e1117`, `#141822`).
- **Signature Accent:** Nebula Cyan (`#06b6d4`, `#22d3ee`) with controlled deep cyan undertones (`rgba(6, 182, 212, 0.15)`).
- **No Purples / Blues Gradients:** Replaced with refined solid and subtle chromatic transitions centered strictly on deep space slate and cyan.

## 2. Token Architecture

### Color Tokens
```css
:root {
  /* Surfaces */
  --bg-base: #090a0f;
  --bg-surface-1: #0e1117;
  --bg-surface-2: #141822;
  --bg-surface-3: #1a202c;
  --bg-surface-hover: rgba(255, 255, 255, 0.04);
  --bg-surface-active: rgba(6, 182, 212, 0.12);

  /* Message Bubbles */
  --msg-in-bg: #141822;
  --msg-in-text: #f1f5f9;
  --msg-in-border: rgba(255, 255, 255, 0.06);
  --msg-out-bg: #0e3b43;
  --msg-out-text: #ecfeff;
  --msg-out-border: rgba(34, 211, 238, 0.25);

  /* Borders & Dividers */
  --border-subtle: rgba(255, 255, 255, 0.08);
  --border-focus: rgba(34, 211, 238, 0.55);
  --border-active: #06b6d4;

  /* Typography */
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --text-faint: #475569;

  /* Nebula Cyan Accents */
  --accent-cyan: #06b6d4;
  --accent-cyan-light: #22d3ee;
  --accent-cyan-dim: rgba(6, 182, 212, 0.14);
  --accent-cyan-border: rgba(6, 182, 212, 0.35);

  /* Semantic */
  --status-online: #10b981;
  --status-warning: #f59e0b;
  --status-danger: #f43f5e;
  --pq-badge: #22d3ee;
}
```

### Typography Hierarchy
- **Base Font:** `'Vazirmatn', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Code / Cryptographic Hash Font:** `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`
- **Scale:**
  - Micro / Meta: `11px`, line-height `1.3`
  - Badges / Hints: `12px`, line-height `1.4`
  - Secondary / Previews: `13px`, line-height `1.4`
  - Body / Messages: `14.5px`, line-height `1.55`
  - Subheadings: `16px`, weight `600`, line-height `1.3`
  - Screen Titles: `20px` to `22px`, weight `700`, line-height `1.2`

### Radii & Geometry
- Elements: buttons (`10px`), input fields (`12px`), cards (`16px`), modals (`20px`), avatars (`50%` pill).
- Speech bubbles: rounded organic corners (`18px`) with asymmetrical tail radius (`4px`) on the sending anchor edge.

### Motion Principles (Emil Kowalski Standard)
- **Composite-only properties:** animations strictly constrain to `transform` and `opacity`.
- **Durations:** fast interactions at `120ms - 180ms`, overlays and dialog entrances at `200ms - 240ms`.
- **Easings:** `cubic-bezier(0.16, 1, 0.3, 1)` (snappy out-cubic) for entrances, and micro spring feel on active buttons (`transform: scale(0.97)`).
- **Reduced Motion:** all keyframes and transitions cleanly collapse when `@media (prefers-reduced-motion: reduce)` is signaled.

### Accessibility (WCAG 2.1 AA)
- Minimum contrast ratio 4.5:1 for body and interaction text.
- Visible high-contrast focus rings (`outline: 2px solid var(--accent-cyan); outline-offset: 2px`).
- Preserved keyboard skip-links (`.skip-link`).

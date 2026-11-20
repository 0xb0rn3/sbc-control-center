# SBC Control Center design system

This design system governs the administration interface for a small Linux microserver. The product is an operational console: users inspect host health, manage network services and review system state. Visual character is restrained, practical and legible.

## Foundations

- **Page job:** operate. Keep host health, networking, services, storage, security, logs and backups easy to find.
- **Voice:** direct, calm and technical. Describe actions and consequences without promotional copy.
- **Default theme:** dark, with the supplied global background art subdued beneath opaque content surfaces.
- **Visual hierarchy:** spacing, type and borders carry structure. Reserve accent color for primary actions and current navigation.

## Color tokens

```css
:root {
  --page: #0b0c10;
  --surface: rgba(17, 18, 22, .94);
  --surface-raised: rgba(24, 25, 30, .97);
  --surface-inset: rgba(8, 9, 12, .84);
  --text: #f1eeee;
  --muted: #b0aaaa;
  --dim: #85807f;
  --line: rgba(236, 225, 222, .13);
  --line-strong: rgba(236, 225, 222, .22);
  --accent: #d28a80;
  --accent-hover: #e5a096;
  --accent-soft: rgba(210, 138, 128, .12);
  --ok: #91b79a;
  --warn: #d0ad73;
  --danger: #d27e7e;
}
```

Use status colors only for actual service/security state and always pair them with text. Avoid gradients, neon accents, decorative glow and excessive shadows.

## Typography and spacing

- Body: system UI stack, 14px base, 1.55 line-height.
- Section headings: 20–22px, semibold.
- Labels and metadata: 9–12px, muted and clearly weighted.
- Data/terminal: system monospace with tabular numerals.
- Use a 4px spacing basis. Standard spacing: 4, 8, 12, 16, 20 and 24px.
- Standard corner radii: 7px and 11px. Interactive targets should be at least 44px high where practical.

## Navigation

- Desktop: persistent categorized left rail for Monitor, Operate and Administer.
- Shared navigation center: searchable dialog with all destinations, launched from the header or `Ctrl+K` / `Cmd+K`.
- Mobile: fixed dock for Home, Network, Services and Console; More opens the same searchable navigation center.
- Active destinations use the accent-soft surface and `aria-current="page"`.
- Search filters destination rows and empty groups; dialog supports Escape/backdrop dismissal and visible focus.

## Motion, accessibility and responsive behavior

- Use short state-driven transitions only. No perpetual or decorative animation.
- Respect `prefers-reduced-motion: reduce`.
- Use semantic `nav`, `main`, headings, labels and buttons.
- Expose the same destinations on desktop and mobile; preserve safe-area spacing and avoid horizontal document overflow at 320px and wider.
- Keyboard controls must be operable and maintain visible focus.

## Performance and dependencies

Prefer native HTML, CSS and browser APIs. Do not add remote scripts, icon fonts or unnecessary runtime libraries to the navigation system.

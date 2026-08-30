/* =============================================================================
   SENTINEL docs — scroll spy.

   Highlights the section currently in view in the sidebar. Purely additive: the
   anchors work exactly the same with scripting off.
   ========================================================================== */

import { $$ } from './ui.js';

function start() {
  const links = $$('#docsNav a[href^="#"]');
  if (links.length === 0 || typeof IntersectionObserver !== 'function') return;

  const byId = new Map(links.map((link) => [link.getAttribute('href').slice(1), link]));
  const sections = Array.from(byId.keys())
    .map((id) => document.getElementById(id))
    .filter(Boolean);

  const setActive = (id) => {
    links.forEach((link) => link.classList.remove('active'));
    byId.get(id)?.classList.add('active');
  };

  const observer = new IntersectionObserver(
    (entries) => {
      // Pick the entry nearest the top of the viewport that is on screen.
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible) setActive(visible.target.id);
    },
    { rootMargin: '-15% 0px -70% 0px', threshold: 0 },
  );

  sections.forEach((section) => observer.observe(section));
  if (sections[0]) setActive(sections[0].id);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}

/* =============================================================================
   SENTINEL — shared UI runtime.

   Every enhancement here is optional and defensive: if one fails, the page
   still reads and every link still works. Loaded by all four pages.
   ========================================================================== */

export const reduceMotion =
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ------------------------------------------------------------- selectors */

export const $ = (sel, scope) => (scope || document).querySelector(sel);
export const $$ = (sel, scope) =>
  Array.from((scope || document).querySelectorAll(sel));

/** Build an element without ever handing a string to innerHTML. */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'html') throw new Error('el(): raw html is not permitted');
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else node.setAttribute(key, String(value));
  }
  for (const child of [].concat(children)) {
    if (child === undefined || child === null || child === false) continue;
    // Duck-type rather than `instanceof Node`, so the helper also works inside
    // a document from another realm (iframe, or a non-browser DOM in tests).
    const isNode = typeof child === 'object' && typeof child.nodeType === 'number';
    node.append(isNode ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Replace a node's children with freshly built ones. */
export function fill(node, children) {
  if (!node) return;
  node.replaceChildren(...[].concat(children).filter(Boolean));
}

export const fmt = {
  num: (n, digits = 0) =>
    Number.isFinite(n) ? Number(n).toFixed(digits) : String(n ?? '—'),
  pct: (n) => `${Math.round(Number(n) || 0)}%`,
  clip: (s, max = 14) => {
    const text = String(s ?? '');
    return text.length > max ? `${text.slice(0, max)}…` : text;
  },
  json: (value) => {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  },
};

/* ------------------------------------------------------------------ toast */

let toastNode = null;
let toastTimer = 0;

export function toast(message) {
  if (!toastNode) {
    toastNode = el('div', { class: 'toast', role: 'status', 'aria-live': 'polite' });
    document.body.append(toastNode);
  }
  toastNode.textContent = message;
  toastNode.classList.add('show');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toastNode.classList.remove('show'), 1800);
}

/* ------------------------------------------------------------------- copy */

async function writeClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for plain-http contexts, where the async clipboard is blocked.
  const ta = el('textarea', { readonly: '' });
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
  document.body.append(ta);
  ta.select();
  document.execCommand('copy');
  ta.remove();
}

/** Wire every `[data-copy]` button to copy the referenced element's text. */
function initCopy() {
  document.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-copy]');
    if (!btn) return;
    const source = document.getElementById(btn.getAttribute('data-copy'));
    if (!source) return;
    writeClipboard(source.textContent.trim())
      .then(() => toast('Copied'))
      .catch(() => toast('Copy failed'));
  });
}

/* -------------------------------------------------------------------- nav */

function initNav() {
  const toggle = $('#navToggle');
  const nav = $('#primaryNav');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    nav.addEventListener('click', (event) => {
      if (event.target.tagName === 'A') {
        nav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Mark the current page in the header nav.
  const here = location.pathname.split('/').pop() || 'index.html';
  $$('#primaryNav a[href]').forEach((link) => {
    const target = link.getAttribute('href').split('#')[0];
    if (target && target === here) link.setAttribute('aria-current', 'page');
  });
}

/* ----------------------------------------------------------------- reveal */

function initReveal() {
  const targets = $$('.reveal');
  if (targets.length === 0) return;
  if (reduceMotion || typeof IntersectionObserver !== 'function') {
    targets.forEach((node) => node.classList.add('in'));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('in');
        observer.unobserve(entry.target);
      });
    },
    { rootMargin: '0px 0px -8% 0px', threshold: 0.08 },
  );
  targets.forEach((node, index) => {
    node.style.transitionDelay = `${Math.min(index % 6, 5) * 55}ms`;
    observer.observe(node);
  });
}

/* ------------------------------------------------------------- count-ups */

function initCounters() {
  const nodes = $$('[data-count]');
  if (nodes.length === 0) return;
  if (reduceMotion || typeof IntersectionObserver !== 'function') return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const node = entry.target;
        observer.unobserve(node);
        const target = Number(node.getAttribute('data-count'));
        if (!Number.isFinite(target)) return;
        const started = performance.now();
        const tick = (now) => {
          const t = Math.min(1, (now - started) / 900);
          const eased = 1 - Math.pow(1 - t, 3);
          node.textContent = String(Math.round(target * eased));
          if (t < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
      });
    },
    { threshold: 0.5 },
  );
  nodes.forEach((node) => observer.observe(node));
}

/* ---------------------------------------------------------------- tablist */

/**
 * Generic ARIA tablist. Buttons carry `data-tab="<panel id>"`; the container
 * carries `data-tabs`. Works for the install tabs and the lab rail alike.
 */
export function initTabs(root = document) {
  $$('[data-tabs]', root).forEach((group) => {
    const buttons = $$('[data-tab]', group);
    const select = (id, focus) => {
      buttons.forEach((btn) => {
        const active = btn.getAttribute('data-tab') === id;
        btn.setAttribute('aria-selected', String(active));
        btn.tabIndex = active ? 0 : -1;
        const panel = document.getElementById(btn.getAttribute('data-tab'));
        if (panel) panel.hidden = !active;
        if (active && focus) btn.focus();
      });
      group.dispatchEvent(new CustomEvent('tabchange', { detail: { id } }));
    };

    buttons.forEach((btn, index) => {
      btn.addEventListener('click', () => select(btn.getAttribute('data-tab')));
      btn.addEventListener('keydown', (event) => {
        const delta =
          event.key === 'ArrowRight' || event.key === 'ArrowDown'
            ? 1
            : event.key === 'ArrowLeft' || event.key === 'ArrowUp'
              ? -1
              : 0;
        if (delta === 0) return;
        event.preventDefault();
        const next = buttons[(index + delta + buttons.length) % buttons.length];
        select(next.getAttribute('data-tab'), true);
      });
    });

    const initial =
      buttons.find((b) => b.getAttribute('aria-selected') === 'true') || buttons[0];
    if (initial) select(initial.getAttribute('data-tab'));
  });
}

/* ------------------------------------------------------- hero lattice bg */

/**
 * The hero backdrop: a square lattice with a diagonal shine band sweeping
 * across it. Canvas rather than CSS so the band can light individual cells.
 */
function initHeroCanvas() {
  const canvas = $('#heroCanvas');
  if (!canvas || typeof canvas.getContext !== 'function') return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const CELL = 34;
  let width = 0;
  let height = 0;
  let raf = 0;

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(1, Math.floor(rect.width));
    height = Math.max(1, Math.floor(rect.height));
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };

  const draw = (time) => {
    ctx.clearRect(0, 0, width, height);

    const cols = Math.ceil(width / CELL) + 1;
    const rows = Math.ceil(height / CELL) + 1;
    // Band position sweeps left→right on a 7s loop.
    const sweep = ((time % 7000) / 7000) * (width + height * 0.6) - height * 0.3;

    ctx.lineWidth = 1;
    for (let cx = 0; cx < cols; cx += 1) {
      for (let cy = 0; cy < rows; cy += 1) {
        const x = cx * CELL;
        const y = cy * CELL;
        // Distance from the diagonal shine band.
        const d = Math.abs(x + y * 0.6 - sweep);
        const glow = Math.max(0, 1 - d / 150);
        const base = 0.05;
        ctx.strokeStyle = `rgba(255,255,255,${base + glow * 0.4})`;
        ctx.strokeRect(x + 0.5, y + 0.5, CELL, CELL);
        if (glow > 0.72) {
          ctx.fillStyle = `rgba(255,255,255,${(glow - 0.72) * 0.5})`;
          ctx.fillRect(x + 1, y + 1, CELL - 1, CELL - 1);
        }
      }
    }
    raf = requestAnimationFrame(draw);
  };

  resize();
  window.addEventListener('resize', resize, { passive: true });

  if (reduceMotion) {
    draw(0);
    cancelAnimationFrame(raf);
    return;
  }
  raf = requestAnimationFrame(draw);

  // Stop burning frames when the tab is hidden.
  document.addEventListener('visibilitychange', () => {
    cancelAnimationFrame(raf);
    if (!document.hidden) raf = requestAnimationFrame(draw);
  });
}

/* ---------------------------------------------------------- hero pipeline */

/** Walk the eight pipeline stages, then hold on the approval gate. */
function initPipeline() {
  const stages = $$('#heroPipeline .stage');
  if (stages.length === 0) return;
  if (reduceMotion) {
    stages.forEach((s) => s.classList.add('on'));
    return;
  }
  let index = 0;
  const step = () => {
    if (index >= stages.length) {
      window.setTimeout(() => {
        stages.forEach((s) => s.classList.remove('on'));
        index = 0;
        window.setTimeout(step, 700);
      }, 2600);
      return;
    }
    stages[index].classList.add('on');
    index += 1;
    window.setTimeout(step, 420);
  };
  window.setTimeout(step, 500);
}

/* ------------------------------------------------------------------- boot */

export function boot() {
  document.documentElement.classList.add('js');
  initNav();
  initCopy();
  initReveal();
  initCounters();
  initTabs();
  initHeroCanvas();
  initPipeline();
  const year = $('#year');
  if (year) year.textContent = String(new Date().getFullYear());
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}

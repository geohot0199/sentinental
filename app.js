/* =============================================================================
   SENTINEL landing page behaviour.

   Dependency-free and defensive: every enhancement is optional, so the page
   still reads and every download link still works if any of this fails.
   ========================================================================== */
(function () {
  "use strict";

  var reduceMotion =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------ utilities */
  function $(selector, scope) {
    return (scope || document).querySelector(selector);
  }
  function $$(selector, scope) {
    return Array.prototype.slice.call((scope || document).querySelectorAll(selector));
  }

  /** Decode the HTML entities used in data-code attributes. */
  function decodeEntities(text) {
    var el = document.createElement("textarea");
    el.innerHTML = text;
    return el.value;
  }

  /** Clipboard write with a fallback for non-secure contexts. */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error("copy failed"));
      } catch (error) {
        reject(error);
      }
    });
  }

  function flashCopied(btn, label) {
    if (!btn) return;
    var original = label || btn.textContent;
    btn.classList.add("is-copied");
    var textEl = $(".copy-label", btn);
    if (textEl) textEl.textContent = "Copied";
    else if (!label) btn.textContent = "Copied";
    window.setTimeout(function () {
      btn.classList.remove("is-copied");
      if (textEl) textEl.textContent = original;
      else if (!label) btn.textContent = original;
    }, 1600);
  }

  /* --------------------------------------------------- copy: small buttons */
  $$("[data-copy-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!target) return;
      copyText(target.textContent.trim()).then(
        function () { flashCopied(btn); },
        function () { /* clipboard unavailable: leave the text selectable */ }
      );
    });
  });

  /* ------------------------------------------------------- copy: code blocks */
  $$(".code[data-code]").forEach(function (block) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "code-copy";
    button.textContent = "copy";
    button.setAttribute("aria-label", "Copy code");
    block.appendChild(button);

    button.addEventListener("click", function () {
      copyText(decodeEntities(block.getAttribute("data-code") || "")).then(
        function () {
          button.textContent = "copied";
          button.classList.add("is-copied");
          window.setTimeout(function () {
            button.textContent = "copy";
            button.classList.remove("is-copied");
          }, 1600);
        },
        function () { button.textContent = "select ⌘C"; }
      );
    });
  });

  /* ------------------------------------------------------------ install tabs */
  var tabs = $$(".tablist .tab");
  function selectTab(tab) {
    tabs.forEach(function (t) {
      var selected = t === tab;
      t.classList.toggle("is-active", selected);
      t.setAttribute("aria-selected", selected ? "true" : "false");
      var panel = document.getElementById(t.getAttribute("aria-controls"));
      if (panel) {
        panel.classList.toggle("is-active", selected);
        panel.hidden = !selected;
      }
    });
  }
  tabs.forEach(function (tab, index) {
    tab.addEventListener("click", function () { selectTab(tab); });
    tab.addEventListener("keydown", function (event) {
      var step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
      if (step === 0) return;
      event.preventDefault();
      var next = tabs[(index + step + tabs.length) % tabs.length];
      next.focus();
      selectTab(next);
    });
  });

  /* ------------------------------------------------------------- mobile nav */
  var navToggle = $("#navToggle");
  var primaryNav = $("#primaryNav");
  if (navToggle && primaryNav) {
    navToggle.addEventListener("click", function () {
      var open = primaryNav.classList.toggle("is-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    $$("a", primaryNav).forEach(function (link) {
      link.addEventListener("click", function () {
        primaryNav.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* -------------------------------------------------------- reveal on scroll */
  var revealables = $$(".reveal");
  if ("IntersectionObserver" in window && !reduceMotion) {
    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          revealObserver.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.06 }
    );
    revealables.forEach(function (el) { revealObserver.observe(el); });
  } else {
    revealables.forEach(function (el) { el.classList.add("is-visible"); });
  }

  /* -------------------------------------------------------------- scrollspy */
  var navLinks = $$(".primary-nav a[href^='#']");
  var sections = navLinks
    .map(function (link) { return document.getElementById(link.getAttribute("href").slice(1)); })
    .filter(Boolean);

  if ("IntersectionObserver" in window && sections.length > 0) {
    var spy = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          navLinks.forEach(function (link) {
            link.classList.toggle(
              "is-active",
              link.getAttribute("href") === "#" + entry.target.id
            );
          });
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    sections.forEach(function (section) { spy.observe(section); });
  }

  /* ------------------------------------------------------- header + to top */
  var header = $("#siteHeader");
  var toTop = $("#toTop");
  var ticking = false;
  function onScroll() {
    if (header) header.classList.toggle("is-stuck", window.scrollY > 12);
    if (toTop) toTop.hidden = window.scrollY < 700;
    ticking = false;
  }
  window.addEventListener("scroll", function () {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(onScroll);
  }, { passive: true });
  onScroll();

  if (toTop) {
    toTop.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
    });
  }

  /* ---------------------------------------------------- hero pipeline animation */
  var pipeline = $("#heroPipeline");
  if (pipeline) {
    var stages = $$(".stage", pipeline);
    if (reduceMotion) {
      stages.forEach(function (stage, i) {
        stage.classList.add(i === stages.length - 1 ? "is-waiting" : "is-done");
      });
    } else {
      var cursor = 0;
      var gate = stages[stages.length - 1];
      window.setInterval(function () {
        if (cursor >= stages.length - 1) {
          // Reset: clear everything and start the run again.
          stages.forEach(function (s) { s.classList.remove("is-done", "is-active", "is-waiting"); });
          cursor = 0;
          return;
        }
        var current = stages[cursor];
        current.classList.remove("is-active");
        current.classList.add("is-done");
        cursor += 1;
        var next = stages[cursor];
        if (next === gate) {
          next.classList.add("is-waiting");
        } else {
          next.classList.add("is-active");
        }
      }, 1250);
      stages[0].classList.add("is-active");
    }
  }

  /* --------------------------------------------------- particle canvas */
  var particlesCanvas = $("#particlesCanvas");
  if (particlesCanvas && typeof window.requestAnimationFrame === "function" && !reduceMotion) {
    var ctx = particlesCanvas.getContext("2d");
    var particles = [];
    var particleCount = 60;

    function resizeParticles() {
      var hero = particlesCanvas.parentElement;
      if (!hero) return;
      particlesCanvas.width = hero.offsetWidth;
      particlesCanvas.height = hero.offsetHeight;
    }

    function createParticle() {
      return {
        x: Math.random() * particlesCanvas.width,
        y: Math.random() * particlesCanvas.height,
        size: Math.random() * 1.5 + 0.3,
        speedX: (Math.random() - 0.5) * 0.3,
        speedY: (Math.random() - 0.5) * 0.3,
        opacity: Math.random() * 0.5 + 0.1,
      };
    }

    function initParticles() {
      resizeParticles();
      particles = [];
      for (var i = 0; i < particleCount; i++) {
        particles.push(createParticle());
      }
    }

    function drawParticles() {
      ctx.clearRect(0, 0, particlesCanvas.width, particlesCanvas.height);
      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        p.x += p.speedX;
        p.y += p.speedY;
        if (p.x < 0 || p.x > particlesCanvas.width) p.speedX *= -1;
        if (p.y < 0 || p.y > particlesCanvas.height) p.speedY *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(34, 211, 238, " + p.opacity + ")";
        ctx.fill();
      }
      // Draw connection lines between close particles
      for (var a = 0; a < particles.length; a++) {
        for (var b = a + 1; b < particles.length; b++) {
          var dx = particles[a].x - particles[b].x;
          var dy = particles[a].y - particles[b].y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(particles[a].x, particles[a].y);
            ctx.lineTo(particles[b].x, particles[b].y);
            ctx.strokeStyle = "rgba(34, 211, 238, " + (0.06 * (1 - dist / 120)) + ")";
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      window.requestAnimationFrame(drawParticles);
    }

    initParticles();
    drawParticles();
    window.addEventListener("resize", resizeParticles);
  }

  /* -------------------------------------------------- animated counters */
  var statEls = $$(".stat dt[data-count]");
  if (statEls.length > 0 && "IntersectionObserver" in window && !reduceMotion) {
    var counterObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          var el = entry.target;
          var target = parseInt(el.getAttribute("data-count"), 10);
          var suffix = el.getAttribute("data-suffix") || "";
          var duration = 1200;
          var start = Date.now();
          function tick() {
            var elapsed = Date.now() - start;
            var progress = Math.min(elapsed / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(target * eased) + suffix;
            if (progress < 1) window.requestAnimationFrame(tick);
          }
          tick();
          counterObserver.unobserve(el);
        });
      },
      { threshold: 0.5 }
    );
    statEls.forEach(function (el) { counterObserver.observe(el); });
  }

  /* ----------------------------------------------------- live GitHub stars */
  var starCount = typeof fetch === "function" ? $("#starCount") : null;
  if (starCount) {
    fetch("https://api.github.com/repos/geohot0199/sentinental", {
      headers: { Accept: "application/vnd.github+json" },
    })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (!data || typeof data.stargazers_count !== "number") return;
        starCount.textContent = "★ " + data.stargazers_count;
        starCount.hidden = false;
      })
      .catch(function () { /* offline or rate limited: leave the badge hidden */ });
  }
})();

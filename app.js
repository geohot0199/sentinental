(function(){
  "use strict";

  var $ = function(s, c){ return (c||document).querySelector(s); };
  var $$ = function(s, c){ return Array.from((c||document).querySelectorAll(s)); };

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Copy buttons */
  function copyText(t){
    if(navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(t);
    var ta=document.createElement("textarea");ta.value=t;ta.style.cssText="position:fixed;top:-999px";
    document.body.appendChild(ta);ta.select();document.execCommand("copy");document.body.removeChild(ta);
    return Promise.resolve();
  }
  $$("[data-copy]").forEach(function(btn){
    btn.addEventListener("click",function(){
      var el=document.getElementById(btn.getAttribute("data-copy"));
      if(!el) return;
      copyText(el.textContent.trim()).then(function(){
        btn.textContent="COPIED";btn.classList.add("copied");
        setTimeout(function(){btn.textContent="COPY";btn.classList.remove("copied")},1500);
      });
    });
  });

  /* Code block copy */
  $$(".code-block[data-code]").forEach(function(block){
    var btn=document.createElement("button");btn.className="copy-btn";btn.textContent="COPY";btn.type="button";
    block.appendChild(btn);
    btn.addEventListener("click",function(){
      var code=block.getAttribute("data-code").replace(/&#10;/g,"\n").replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">");
      copyText(code).then(function(){
        btn.textContent="COPIED";btn.classList.add("copied");
        setTimeout(function(){btn.textContent="COPY";btn.classList.remove("copied")},1500);
      });
    });
  });

  /* Tabs */
  $$(".tab-bar .tab").forEach(function(tab){
    tab.addEventListener("click",function(){
      var bar=tab.parentElement;
      var tabs=bar.parentElement;
      $$(".tab",bar).forEach(function(t){t.classList.remove("active")});
      tab.classList.add("active");
      $$(".tab-panel",tabs).forEach(function(p){p.classList.remove("active");p.hidden=true});
      var panel=document.getElementById(tab.getAttribute("data-panel"));
      if(panel){panel.classList.add("active");panel.hidden=false}
    });
  });

  /* Mobile nav */
  var toggle=$("#navToggle"),links=$("#navLinks");
  if(toggle&&links){
    toggle.addEventListener("click",function(){
      var open=links.classList.toggle("open");
      toggle.classList.toggle("open",open);
      toggle.setAttribute("aria-expanded",open?"true":"false");
    });
    $$("a",links).forEach(function(a){a.addEventListener("click",function(){
      links.classList.remove("open");toggle.classList.remove("open");toggle.setAttribute("aria-expanded","false");
    })});
  }

  /* Scroll effects */
  var nav=$("#nav"),toTop=$("#toTop"),ticking=false;
  function onScroll(){
    if(nav) nav.classList.toggle("scrolled",window.scrollY>10);
    if(toTop) toTop.hidden=window.scrollY<600;
    ticking=false;
  }
  window.addEventListener("scroll",function(){if(!ticking){ticking=true;requestAnimationFrame(onScroll)}},{passive:true});
  onScroll();
  if(toTop) toTop.addEventListener("click",function(){window.scrollTo({top:0,behavior:reduceMotion?"auto":"smooth"})});

  /* Reveal on scroll */
  var revs=$$(".reveal");
  if("IntersectionObserver" in window && !reduceMotion){
    var obs=new IntersectionObserver(function(entries){
      entries.forEach(function(e){if(e.isIntersecting){e.target.classList.add("vis");obs.unobserve(e.target)}});
    },{rootMargin:"0px 0px -8% 0px",threshold:.05});
    revs.forEach(function(el){obs.observe(el)});
  } else { revs.forEach(function(el){el.classList.add("vis")}) }

  /* Animated counters */
  var counters=$$("[data-count]");
  if(counters.length && "IntersectionObserver" in window && !reduceMotion){
    var cobs=new IntersectionObserver(function(entries){
      entries.forEach(function(e){
        if(!e.isIntersecting) return;
        var el=e.target,target=parseInt(el.getAttribute("data-count"),10),dur=1000,start=Date.now();
        (function tick(){
          var p=Math.min((Date.now()-start)/dur,1),v=Math.round(target*(1-Math.pow(1-p,3)));
          el.textContent=v;if(p<1)requestAnimationFrame(tick);
        })();
        cobs.unobserve(el);
      });
    },{threshold:.5});
    counters.forEach(function(el){cobs.observe(el)});
  }

  /* Pipeline animation */
  var pipe=$("#heroPipe");
  if(pipe){
    var rows=$$(".pipe-row",pipe);
    if(reduceMotion){
      rows.forEach(function(r,i){r.classList.add(i===rows.length-1?"wait":"done")});
    } else {
      var cur=0,last=rows.length-1;
      rows[0].classList.add("active");
      setInterval(function(){
        if(cur>=last){rows.forEach(function(r){r.classList.remove("active","done","wait")});cur=0;rows[0].classList.add("active");return}
        rows[cur].classList.remove("active");rows[cur].classList.add("done");cur++;
        rows[cur].classList.add(cur===last?"wait":"active");
      },1200);
    }
  }

})();

// Small progressive enhancements. The pages read fine without this script.
(function () {
  // theme: the button switches between dark and light and remembers the choice
  var root = document.documentElement;
  var toggle = document.getElementById("theme");
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener("click", function () {
      var light = root.getAttribute("data-theme") === "light" ||
        (!root.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: light)").matches);
      var next = light ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("pw-theme", next); } catch (e) {}
    });
  }

  // copy button on code blocks (documentation pages, and blocks marked data-copy)
  if (navigator.clipboard) {
    document.querySelectorAll("article pre, pre[data-copy]").forEach(function (pre) {
      var b = document.createElement("button");
      b.className = "copy";
      b.type = "button";
      b.textContent = "Copy";
      b.addEventListener("click", function () {
        navigator.clipboard.writeText((pre.querySelector("code") || pre).innerText.trim()).then(function () {
          b.textContent = "Copied";
          setTimeout(function () { b.textContent = "Copy"; }, 1500);
        });
      });
      pre.appendChild(b);
    });
  }

  // sidebar filter: type to narrow the list of pages
  var filter = document.getElementById("navfilter");
  if (filter) {
    filter.hidden = false;
    filter.addEventListener("input", function () {
      var q = filter.value.trim().toLowerCase();
      document.querySelectorAll(".side ul").forEach(function (ul) {
        var any = false;
        ul.querySelectorAll("li").forEach(function (li) {
          var show = li.textContent.toLowerCase().indexOf(q) !== -1;
          li.hidden = !show;
          any = any || show;
        });
        ul.hidden = !any;
        if (ul.previousElementSibling) ul.previousElementSibling.hidden = !any;
      });
    });
  }

  var article = document.querySelector("article");
  if (!article) return;

  // wide tables scroll inside their own box instead of stretching the page
  article.querySelectorAll("table").forEach(function (t) {
    var wrap = document.createElement("div");
    wrap.className = "tablewrap";
    t.parentNode.insertBefore(wrap, t);
    wrap.appendChild(t);
  });

  // "On this page" from the h2 and h3 headings, and a link icon on each
  var toc = document.getElementById("toc");
  var heads = article.querySelectorAll("h2[id], h3[id]");
  var links = {};
  heads.forEach(function (h) {
    var a = document.createElement("a");
    a.className = "anchor";
    a.href = "#" + h.id;
    a.setAttribute("aria-label", "Link to this section");
    a.textContent = "#";
    var title = h.textContent;
    h.appendChild(a);
    if (!toc) return;
    var li = document.createElement("li");
    if (h.tagName === "H3") li.className = "sub";
    var link = document.createElement("a");
    link.href = "#" + h.id;
    link.textContent = title;
    li.appendChild(link);
    toc.appendChild(li);
    links[h.id] = link;
  });
  if (toc && heads.length > 2) {
    toc.parentNode.hidden = false;
    // mark the section being read
    if ("IntersectionObserver" in window) {
      var seen = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          Object.keys(links).forEach(function (id) { links[id].classList.remove("here"); });
          links[e.target.id].classList.add("here");
        });
      }, { rootMargin: "-70px 0px -70% 0px" });
      heads.forEach(function (h) { seen.observe(h); });
    }
  }

  // on small screens the contents list starts closed
  var d = document.querySelector(".side details");
  if (d && window.matchMedia("(max-width: 800px)").matches) d.open = false;
})();

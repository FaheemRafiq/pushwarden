// Small progressive enhancements. The pages read fine without this script.
(function () {
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
  heads.forEach(function (h) {
    var a = document.createElement("a");
    a.className = "anchor";
    a.href = "#" + h.id;
    a.setAttribute("aria-label", "Link to this section");
    a.textContent = "#";
    h.appendChild(a);
    if (!toc) return;
    var li = document.createElement("li");
    if (h.tagName === "H3") li.className = "sub";
    var link = document.createElement("a");
    link.href = "#" + h.id;
    link.textContent = h.firstChild.textContent;
    li.appendChild(link);
    toc.appendChild(li);
  });
  if (toc && heads.length > 2) toc.parentNode.hidden = false;

  // copy button on code blocks
  if (navigator.clipboard) {
    article.querySelectorAll("pre").forEach(function (pre) {
      var b = document.createElement("button");
      b.className = "copy";
      b.type = "button";
      b.textContent = "Copy";
      b.addEventListener("click", function () {
        navigator.clipboard.writeText(pre.querySelector("code").innerText).then(function () {
          b.textContent = "Copied";
          setTimeout(function () { b.textContent = "Copy"; }, 1500);
        });
      });
      pre.appendChild(b);
    });
  }

  // on small screens the contents list starts closed
  var d = document.querySelector(".side details");
  if (d && window.matchMedia("(max-width: 800px)").matches) d.open = false;
})();

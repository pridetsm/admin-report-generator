// Report Builder — tiny vanilla helpers (no framework, internal-network safe).
(function () {
  "use strict";

  // ---- csrf helper (for same-origin POSTs) ----
  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[2]) : null;
  }

  // A page rendered before the csrftoken cookie was rotated (Django rotates it on every
  // login — and the 15-minute idle timeout means a re-login is common while a long
  // selection/annotation form sits open) carries a token that no longer matches the cookie,
  // which Django rejects with a bare "CSRF verification failed" 403. The cookie is always
  // the current one, so re-stamp the hidden field from it at submit time.
  document.addEventListener("submit", function (e) {
    var field = e.target.querySelector && e.target.querySelector("input[name=csrfmiddlewaretoken]");
    var cookie = getCookie("csrftoken");
    if (field && cookie) field.value = cookie;
  }, true);

  // ---- top-bar dropdowns: settings (+notifications) and profile (one open at a time) ----
  var menus = [
    ["settingsMenu", "settingsToggle"],
    ["profileMenu", "profileToggle"],
  ].map(function (pair) {
    return { menu: document.getElementById(pair[0]), toggle: document.getElementById(pair[1]) };
  }).filter(function (m) { return m.menu && m.toggle; });

  function closeMenus(except) {
    menus.forEach(function (m) {
      if (m.menu === except) return;
      m.menu.classList.remove("open");
      m.toggle.setAttribute("aria-expanded", "false");
    });
  }
  // opening the hamburger counts as "seeing" notifications -> clear the red dot
  function markNotificationsSeen(menu) {
    var url = menu.getAttribute("data-seen-url");
    var dot = document.getElementById("notifDot");
    if (!url || !dot) return;
    fetch(url, { method: "POST", headers: { "X-CSRFToken": getCookie("csrftoken") || "" },
                 credentials: "same-origin" }).catch(function () {});
    dot.remove();
  }
  menus.forEach(function (m) {
    m.toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = m.menu.classList.toggle("open");
      m.toggle.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) { closeMenus(m.menu); if (m.menu.id === "settingsMenu") markNotificationsSeen(m.menu); }
    });
  });
  document.addEventListener("click", function (e) {
    menus.forEach(function (m) {
      if (!m.menu.contains(e.target)) {
        m.menu.classList.remove("open");
        m.toggle.setAttribute("aria-expanded", "false");
      }
    });
  });

  // ---- full-page loading spinner on navigation / reload ----
  var spinner = document.getElementById("pageSpinner");
  var spinnerSafety = null;
  function showSpinner() {
    if (!spinner) return;
    spinner.classList.add("show");
    clearTimeout(spinnerSafety);
    spinnerSafety = setTimeout(hideSpinner, 15000);   // never let it stick
  }
  function hideSpinner() { if (spinner) { spinner.classList.remove("show"); clearTimeout(spinnerSafety); } }
  window.skipSpinnerOnce = function () { window.__skipSpinner = true; };
  if (spinner) {
    // real navigations away from the page (links, reloads, form submits)
    window.addEventListener("beforeunload", function () {
      if (window.__skipSpinner) { window.__skipSpinner = false; return; }   // e.g. a file download keeps the page
      showSpinner();
    });
    // if the page is restored from the back/forward cache, make sure it's hidden again
    window.addEventListener("pageshow", hideSpinner);
    // ignore in-page anchors / new-tab / download links
    document.addEventListener("click", function (e) {
      var a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      var href = a.getAttribute("href");
      if (!href || href.charAt(0) === "#" || a.target === "_blank" || a.hasAttribute("download")) return;
      showSpinner();
    });
  }

  // ---- navigation drawer (opened from the app title) ----
  var drawer = document.getElementById("drawer");
  var backdrop = document.getElementById("drawerBackdrop");
  var drawerToggle = document.getElementById("drawerToggle");
  var drawerClose = document.getElementById("drawerClose");
  function openDrawer() {
    if (!drawer) return;
    drawer.classList.add("open"); backdrop.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    if (drawerToggle) drawerToggle.setAttribute("aria-expanded", "true");
  }
  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove("open"); backdrop.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    if (drawerToggle) drawerToggle.setAttribute("aria-expanded", "false");
  }
  if (drawerToggle) drawerToggle.addEventListener("click", function (e) { e.stopPropagation(); openDrawer(); });
  if (drawerClose) drawerClose.addEventListener("click", closeDrawer);
  if (backdrop) backdrop.addEventListener("click", closeDrawer);

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      closeMenus(null);
      closeDrawer();
    }
  });

  // ---- clickable history rows -> compact report detail ----
  document.querySelectorAll("tr.rowlink[data-href]").forEach(function (tr) {
    tr.addEventListener("click", function () { window.location.href = tr.getAttribute("data-href"); });
  });

  // ---- collapsible system cards ----
  document.addEventListener("click", function (e) {
    var h = e.target.closest && e.target.closest("[data-collapsible] > header");
    // buttons inside a header (e.g. "remove job") act on the card, not on its fold state
    if (!h || (e.target.closest && e.target.closest("button[data-remove-job]"))) return;
    h.parentElement.classList.toggle("collapsed");
  });

  // ---- Configuration form: prometheus.yml as add/remove rows ----------------------------
  // Field names carry their own indexes (job__3__name, sc__3__0__targets, …) and the server
  // discovers them by scanning the POST. So removing a row can just delete the DOM node —
  // nothing renumbers, and nothing gets mis-mapped onto a neighbouring job.
  var promForm = document.getElementById("promForm");
  if (promForm) {
    var jobList = document.getElementById("jobList");

    function fill(tplId, values) {
      var tpl = document.getElementById(tplId);
      var html = tpl.innerHTML;
      Object.keys(values).forEach(function (k) {
        html = html.split("__" + k + "__").join(values[k]);
      });
      var box = document.createElement("div");
      box.innerHTML = html.trim();
      return box.firstElementChild;
    }
    // next index for a set of siblings: one past the highest in use, so new rows never
    // collide with an existing (or previously removed) one
    function nextIndex(scope, selector, attr) {
      var max = -1;
      scope.querySelectorAll(selector).forEach(function (el) {
        var n = parseInt(attr ? el.getAttribute(attr) : el.name.match(/(\d+)/)[1], 10);
        if (!isNaN(n) && n > max) max = n;
      });
      return max + 1;
    }
    function nextNamedIndex(scope, prefixRe) {
      var max = -1;
      scope.querySelectorAll("input[name]").forEach(function (el) {
        var m = prefixRe.exec(el.name);
        if (m) { var n = parseInt(m[1], 10); if (n > max) max = n; }
      });
      return max + 1;
    }
    function refreshJob(job) {
      var count = job.querySelectorAll("[data-groups] > .cfg-group").length;
      var badge = job.querySelector("[data-group-count]");
      if (badge) badge.textContent = count;
    }

    document.getElementById("addJob").addEventListener("click", function () {
      var j = nextIndex(jobList, ".cfg-job", "data-job");
      var job = fill("tplJob", { J: j });
      jobList.appendChild(job);
      job.querySelector("[data-job-name]").focus();
    });

    promForm.addEventListener("click", function (e) {
      var t = e.target;
      if (!t.closest) return;

      var addGroup = t.closest("[data-add-group]");
      if (addGroup) {
        var job = addGroup.closest(".cfg-job");
        var groups = job.querySelector("[data-groups]");
        var g = nextIndex(groups, ".cfg-group", "data-group");
        groups.appendChild(fill("tplGroup", { J: job.getAttribute("data-job"), G: g }));
        refreshJob(job);
        return;
      }
      var addLabel = t.closest("[data-add-label]");
      if (addLabel) {
        var group = addLabel.closest(".cfg-group");
        var kv = group.querySelector('[data-kv="labels"]');
        var jIdx = group.closest(".cfg-job").getAttribute("data-job");
        var gIdx = group.getAttribute("data-group");
        kv.appendChild(fill("tplLabel", {
          J: jIdx, G: gIdx, N: nextNamedIndex(kv, /__xkey__(\d+)$/)
        }));
        return;
      }
      var addExt = t.closest("[data-add-extlabel]");
      if (addExt) {
        var box = document.querySelector('[data-kv="extlabels"]');
        box.appendChild(fill("tplExtLabel", { N: nextNamedIndex(box, /^g_extlabel_key__(\d+)$/) }));
        return;
      }
      var rmJob = t.closest("[data-remove-job]");
      if (rmJob) {
        var card = rmJob.closest(".cfg-job");
        var name = (card.querySelector("[data-job-name]") || {}).value || "this job";
        if (confirm("Remove the scrape job “" + name + "”?\n\nNothing is written until you save.")) {
          card.remove();
        }
        return;
      }
      var rmGroup = t.closest("[data-remove-group]");
      if (rmGroup) {
        var grp = rmGroup.closest(".cfg-group");
        var owner = grp.closest(".cfg-job");
        grp.remove();
        refreshJob(owner);
        return;
      }
      var rm = t.closest("[data-remove]");
      if (rm) rm.closest(".cfg-kv-row").remove();
    });

    // keep each collapsed job card's header in step with the name being typed inside it
    promForm.addEventListener("input", function (e) {
      if (!e.target.matches("[data-job-name]")) return;
      var title = e.target.closest(".cfg-job").querySelector("[data-job-title]");
      if (title) title.textContent = e.target.value || "(unnamed job)";
    });
  }

  // ---- role scopes: select-all / clear per role ----
  document.querySelectorAll("[data-scope-all], [data-scope-none]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var on = btn.hasAttribute("data-scope-all");
      var card = btn.closest(".card");
      card.querySelectorAll('[data-scope-group] input[type="checkbox"]').forEach(function (cb) {
        cb.checked = on;
      });
    });
  });
})();

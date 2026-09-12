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
    // A button in the header acts on the card itself, so it must not also fold it. Matched on
    // "any button" rather than a specific one: the next control added to a header would
    // otherwise silently collapse the thing it was meant to act on.
    if (!h || (e.target.closest && e.target.closest("header button"))) return;
    h.parentElement.classList.toggle("collapsed");
  });

  // ---- Configuration screens: add/remove rows on the prometheus.yml forms ---------------
  // Field names carry their own indexes (sc__3__0__targets, …) and the server discovers them
  // by scanning the POST, so removing a row is just deleting the DOM node — nothing renumbers
  // and nothing gets mis-mapped onto a neighbouring host.
  //
  // Shared by the Prometheus screen (external labels) and Topology (hosts), because both post
  // the same field names into the same parser.
  var promForm = document.getElementById("promForm");
  if (promForm) {
    function fill(tplId, values) {
      var tpl = document.getElementById(tplId);
      if (!tpl) return null;
      var html = tpl.innerHTML;
      Object.keys(values).forEach(function (k) {
        html = html.split("__" + k + "__").join(values[k]);
      });
      var box = document.createElement("div");
      box.innerHTML = html.trim();
      return box.firstElementChild;
    }
    // one past the highest index in use, so a new row never collides with an existing one —
    // or with one that was removed earlier in this same editing session
    function nextNamedIndex(scope, prefixRe) {
      var max = -1;
      scope.querySelectorAll("input[name]").forEach(function (el) {
        var m = prefixRe.exec(el.name);
        if (m) { var n = parseInt(m[1], 10); if (n > max) max = n; }
      });
      return max + 1;
    }

    // ---- Topology: add a host to a chosen scrape job ----
    var addHost = document.getElementById("addHost");
    if (addHost) {
      addHost.addEventListener("click", function () {
        var select = document.getElementById("addHostJob");
        var option = select.options[select.selectedIndex];
        // The job's next free group index is carried on the option and bumped here, so adding
        // several hosts to one job in a row does not hand them all the same index.
        var g = parseInt(option.getAttribute("data-next-group"), 10);
        option.setAttribute("data-next-group", g + 1);
        var row = fill("tplHost", { J: select.value, G: g, JOBNAME: option.textContent });
        var box = document.getElementById("newHosts");
        box.appendChild(row);
        row.querySelector("textarea").focus();
      });
    }

    promForm.addEventListener("click", function (e) {
      var t = e.target;
      if (!t.closest) return;

      var addExt = t.closest("[data-add-extlabel]");
      if (addExt) {
        var box = document.querySelector('[data-kv="extlabels"]');
        box.appendChild(fill("tplExtLabel", { N: nextNamedIndex(box, /^g_extlabel_key__(\d+)$/) }));
        return;
      }
      var rmHost = t.closest("[data-remove-host]");
      if (rmHost) {
        var host = rmHost.closest(".cfg-group");
        var name = (host.querySelector("input[name$='__l_display']") || {}).value ||
                   (host.querySelector("textarea") || {}).value || "this host";
        if (confirm("Remove " + name + " from the configuration?\n\nNothing is written until you save.")) {
          host.remove();
        }
        return;
      }
      var rm = t.closest("[data-remove]");
      if (rm) rm.closest(".cfg-kv-row").remove();
    });
  }


  // ---- role scopes: select-all / clear per role (search-filtered rows only, if any are hidden) ----
  document.querySelectorAll("[data-scope-all], [data-scope-none]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var on = btn.hasAttribute("data-scope-all");
      var card = btn.closest(".card");
      card.querySelectorAll('[data-scope-group] input[type="checkbox"]').forEach(function (cb) {
        var opt = cb.closest(".scope-opt");
        if (opt && opt.style.display === "none") return;
        cb.checked = on;
      });
    });
  });

  // ---- scope-grid search: filter .scope-opt rows by typed text ----
  document.querySelectorAll("[data-scope-search]").forEach(function (input) {
    var card = input.closest(".card") || input.parentElement;
    var opts = Array.prototype.slice.call(card.querySelectorAll('[data-scope-group] .scope-opt'));
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      opts.forEach(function (opt) {
        opt.style.display = (!q || opt.textContent.toLowerCase().indexOf(q) > -1) ? "" : "none";
      });
    });
  });

  // ---- grouped-table search: filter data-search-row rows (and hide a group's own
  // data-search-group header when every row under it is hidden) by typed text. Generic --
  // any table grouped into sections can opt in with these two data attributes, same idea as
  // the scope-grid search above but for a plain <table> instead of a checkbox grid (added
  // 2026-09-05 for Configuration > System Alerts' freshness-checks table, grouped by system).
  //
  // data-search-group-prefix (added same day for the Alert groups table's own two-level
  // Type > Sub type hierarchy: "make the system hierarchy more readable... following the
  // already established structure") lets a PARENT header (e.g. "System Alert") stay visible
  // if ANY row whose own data-search-group starts with that prefix (e.g. "system:staleness")
  // is still visible, without needing every row to repeat the parent's own group name.
  document.querySelectorAll("[data-table-search]").forEach(function (input) {
    var table = document.querySelector(input.getAttribute("data-table-search"));
    if (!table) return;
    var rows = Array.prototype.slice.call(table.querySelectorAll("tr[data-search-row]"));
    var groups = Array.prototype.slice.call(table.querySelectorAll("tr[data-search-group]"));
    var prefixGroups = Array.prototype.slice.call(table.querySelectorAll("tr[data-search-group-prefix]"));
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      rows.forEach(function (row) {
        row.style.display = (!q || row.textContent.toLowerCase().indexOf(q) > -1) ? "" : "none";
      });
      groups.forEach(function (g) {
        var name = g.getAttribute("data-search-group");
        var anyVisible = rows.some(function (row) {
          return row.getAttribute("data-search-group") === name && row.style.display !== "none";
        });
        g.style.display = anyVisible ? "" : "none";
      });
      prefixGroups.forEach(function (g) {
        var prefix = g.getAttribute("data-search-group-prefix");
        var anyVisible = rows.some(function (row) {
          var rg = row.getAttribute("data-search-group") || "";
          return rg.indexOf(prefix) === 0 && row.style.display !== "none";
        });
        g.style.display = anyVisible ? "" : "none";
      });
    });
  });
})();

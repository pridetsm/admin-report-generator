// Report Builder — tiny vanilla helpers (no framework, internal-network safe).
(function () {
  "use strict";

  // ---- page theme toggle (persists to localStorage; independent of the *report* theme) ----
  var root = document.documentElement;
  var saved = localStorage.getItem("pageTheme");
  if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);

  function currentTheme() {
    return root.getAttribute("data-theme") ||
      (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  var toggle = document.getElementById("themeToggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      localStorage.setItem("pageTheme", next);
    });
  }

  // ---- csrf helper (for same-origin POSTs) ----
  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[2]) : null;
  }

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
  document.querySelectorAll("[data-collapsible] > header").forEach(function (h) {
    h.addEventListener("click", function () {
      h.parentElement.classList.toggle("collapsed");
    });
  });
})();

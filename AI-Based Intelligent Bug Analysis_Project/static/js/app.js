/**
 * AI-Based Intelligent Bug Analysis System
 * Client-Side Application Script & Theme Controller
 */

(function () {
  "use strict";

  const THEME_STORAGE_KEY = "bug_analyzer_theme";

  // Initialize theme from storage or system preference
  function initTheme() {
    const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    if (savedTheme) {
      document.documentElement.setAttribute("data-theme", savedTheme);
      updateThemeButtonText(savedTheme);
    } else {
      // Default to light for clean developer tool aesthetic
      document.documentElement.setAttribute("data-theme", "light");
      updateThemeButtonText("light");
    }
  }

  function updateThemeButtonText(theme) {
    const btn = document.getElementById("theme-toggle-btn");
    if (!btn) return;
    if (theme === "dark") {
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"></circle>
          <line x1="12" y1="1" x2="12" y2="3"></line>
          <line x1="12" y1="21" x2="12" y2="23"></line>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
          <line x1="1" y1="12" x2="3" y2="12"></line>
          <line x1="21" y1="12" x2="23" y2="12"></line>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg> Light Mode`;
    } else {
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg> Dark Mode`;
    }
  }

  window.toggleTheme = function () {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    updateThemeButtonText(newTheme);

    // If charts.js is active, trigger dynamic color refresh
    if (typeof window.onThemeChanged === "function") {
      window.onThemeChanged(newTheme);
    }
  };

  // Run on DOM ready
  document.addEventListener("DOMContentLoaded", function () {
    initTheme();

    // Setup theme button event
    const themeBtn = document.getElementById("theme-toggle-btn");
    if (themeBtn) {
      themeBtn.addEventListener("click", window.toggleTheme);
    }

    // Auto-dismiss alert after 6 seconds if present
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach(function (alert) {
      setTimeout(function () {
        alert.style.transition = "opacity 0.4s ease";
        alert.style.opacity = "0";
        setTimeout(function () { alert.remove(); }, 400);
      }, 7000);
    });
  });
})();

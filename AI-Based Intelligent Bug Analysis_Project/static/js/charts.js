/**
 * AI-Based Intelligent Bug Analysis System
 * Chart.js Integration with Theme Awareness
 */

(function () {
  "use strict";

  let severityChartInstance = null;
  let categoryChartInstance = null;

  function getThemeColors() {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    return {
      text: isDark ? "#9ca3af" : "#64748b",
      grid: isDark ? "#2d3748" : "#e2e8f0",
      tooltipBg: isDark ? "#1f2937" : "#0f172a",
      tooltipText: "#ffffff"
    };
  }

  window.initDashboardCharts = function (severityData, categoryLabels, categoryCounts) {
    if (typeof Chart === "undefined") {
      console.warn("Chart.js library is not loaded.");
      return;
    }

    const colors = getThemeColors();

    // 1. Severity Distribution (Doughnut Chart)
    const sevCanvas = document.getElementById("severityChart");
    if (sevCanvas) {
      const ctx = sevCanvas.getContext("2d");
      severityChartInstance = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels: ["Critical", "High", "Medium", "Low"],
          datasets: [{
            data: [
              severityData.Critical || 0,
              severityData.High || 0,
              severityData.Medium || 0,
              severityData.Low || 0
            ],
            backgroundColor: ["#dc2626", "#ea580c", "#0284c7", "#16a34a"],
            borderWidth: 2,
            borderColor: document.documentElement.getAttribute("data-theme") === "dark" ? "#111827" : "#ffffff"
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                color: colors.text,
                font: { size: 12, family: "-apple-system, sans-serif" },
                padding: 14
              }
            }
          },
          cutout: "65%"
        }
      });
    }

    // 2. Category Distribution (Bar Chart)
    const catCanvas = document.getElementById("categoryChart");
    if (catCanvas) {
      const ctxCat = catCanvas.getContext("2d");
      categoryChartInstance = new Chart(ctxCat, {
        type: "bar",
        data: {
          labels: categoryLabels,
          datasets: [{
            label: "Bug Count",
            data: categoryCounts,
            backgroundColor: "#2563eb",
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: "y",
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { color: colors.grid },
              ticks: { color: colors.text, precision: 0 }
            },
            y: {
              grid: { display: false },
              ticks: { color: colors.text }
            }
          }
        }
      });
    }
  };

  // Callback called by app.js when theme toggles
  window.onThemeChanged = function (newTheme) {
    const colors = getThemeColors();

    if (severityChartInstance) {
      severityChartInstance.data.datasets[0].borderColor = newTheme === "dark" ? "#111827" : "#ffffff";
      if (severityChartInstance.options.plugins.legend) {
        severityChartInstance.options.plugins.legend.labels.color = colors.text;
      }
      severityChartInstance.update();
    }

    if (categoryChartInstance) {
      if (categoryChartInstance.options.scales.x) {
        categoryChartInstance.options.scales.x.grid.color = colors.grid;
        categoryChartInstance.options.scales.x.ticks.color = colors.text;
      }
      if (categoryChartInstance.options.scales.y) {
        categoryChartInstance.options.scales.y.ticks.color = colors.text;
      }
      categoryChartInstance.update();
    }
  };
})();

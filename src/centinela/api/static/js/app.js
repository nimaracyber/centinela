/* Centinela — JS mínimo del dashboard (vanilla, sin dependencias; CSP: script-src 'self').
 * 1. Botones "copiar" (hashes, links desactivados).
 * 2. Resumen: refresca los KPIs cada 30 s desde /api/v1/stats (solo con la pestaña visible).
 * Nada de esto es necesario para usar el dashboard: sin JS todo sigue funcionando.
 */
(function () {
  "use strict";

  var REFRESH_MS = 30000;

  function formatInt(n) {
    var value = Math.max(0, Math.floor(Number(n) || 0));
    return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  }

  function fallbackCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "visually-hidden";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(area);
    return ok;
  }

  function showCopied(button, ok) {
    var feedback = button.querySelector(".copy-feedback");
    if (!feedback) {
      return;
    }
    feedback.textContent = ok ? "Copiado" : "No se pudo copiar";
    window.setTimeout(function () {
      feedback.textContent = "";
    }, 1600);
  }

  function setupCopyButtons() {
    document.addEventListener("click", function (event) {
      var target = event.target;
      var button = target && target.closest ? target.closest("[data-copy]") : null;
      if (!button) {
        return;
      }
      var text = button.getAttribute("data-copy") || "";
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(
          function () {
            showCopied(button, true);
          },
          function () {
            showCopied(button, fallbackCopy(text));
          }
        );
      } else {
        showCopied(button, fallbackCopy(text));
      }
    });
  }

  function updateKpis(prefix, stats) {
    var byLevel = stats.by_level || {};
    var values = {
      total: stats.total,
      suspicious: byLevel.suspicious,
      malicious: byLevel.malicious,
      error: byLevel.error
    };
    Object.keys(values).forEach(function (key) {
      var node = document.querySelector('[data-kpi="' + prefix + "." + key + '"]');
      if (node) {
        node.textContent = formatInt(values[key]);
      }
    });
  }

  function fetchStats(hours) {
    return fetch("/api/v1/stats?hours=" + hours, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store"
    }).then(function (response) {
      if (response.status === 401) {
        window.location.reload(); // la sesión venció: el servidor manda al login
        throw new Error("sesión vencida");
      }
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.json();
    });
  }

  function setupAutoRefresh() {
    if (document.body.getAttribute("data-autorefresh") !== "stats" || !window.fetch) {
      return;
    }
    var status = document.getElementById("refresh-status");
    function refresh() {
      if (document.hidden) {
        return;
      }
      Promise.all([fetchStats(24), fetchStats(168)])
        .then(function (results) {
          updateKpis("24h", results[0]);
          updateKpis("7d", results[1]);
          if (status) {
            var now = new Date();
            var hh = String(now.getHours()).padStart(2, "0");
            var mm = String(now.getMinutes()).padStart(2, "0");
            status.textContent = "Actualizado a las " + hh + ":" + mm + ".";
          }
        })
        .catch(function () {
          if (status) {
            status.textContent = "No se pudo actualizar; se reintenta en 30 segundos.";
          }
        });
    }
    window.setInterval(refresh, REFRESH_MS);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) {
        refresh();
      }
    });
  }

  function init() {
    setupCopyButtons();
    setupAutoRefresh();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

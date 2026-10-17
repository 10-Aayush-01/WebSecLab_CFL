'use strict';

/**
 * Dashboard charts.
 *
 * Data comes from GET /dashboard/data rather than an inline script block,
 * because inline script is forbidden everywhere except the XSS lab.
 *
 * Colours are read from the CSS custom properties at render time, and the
 * charts are rebuilt on the `themechange` event, so they follow the light/dark
 * toggle instead of being hard-coded to one palette.
 */

(function () {
  const charts = { distribution: null, timeline: null };
  let data = null;

  function tokens() {
    const styles = getComputedStyle(document.documentElement);
    const read = (name) => styles.getPropertyValue(name).trim();
    return {
      series1: read('--chart-series-1') || '#1F3A5F',
      series2: read('--chart-series-2') || '#526273',
      series3: read('--chart-series-3') || '#B42318',
      grid: read('--chart-grid') || '#E3E8EE',
      muted: read('--text-3') || '#6B7280',
      surface: read('--surface') || '#FFFFFF'
    };
  }

  function showEmpty(canvas, text) {
    const container = canvas.parentElement;
    container.innerHTML = '';
    const paragraph = document.createElement('p');
    paragraph.className = 'ws-small ws-muted';
    paragraph.textContent = text;
    container.appendChild(paragraph);
  }

  function destroy(name) {
    if (charts[name]) {
      charts[name].destroy();
      charts[name] = null;
    }
  }

  function renderDistribution(canvas, series) {
    const total = series.values.reduce((sum, value) => sum + value, 0);

    if (total === 0) {
      destroy('distribution');
      showEmpty(canvas, 'No security events have been recorded yet.');
      return;
    }

    const palette = tokens();
    destroy('distribution');

    charts.distribution = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: series.labels,
        datasets: [
          {
            data: series.values,
            backgroundColor: [palette.series3, palette.series1, palette.series2, palette.muted],
            borderColor: palette.surface,
            borderWidth: 2,
            hoverOffset: 4
          }
        ]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 10,
              boxHeight: 10,
              usePointStyle: true,
              color: palette.muted,
              font: { size: 12 },
              padding: 12
            }
          },
          tooltip: {
            backgroundColor: palette.series1,
            displayColors: false,
            padding: 8,
            callbacks: {
              label: (item) => {
                const share = total === 0 ? 0 : Math.round((item.parsed / total) * 100);
                return `${item.label}: ${item.parsed} (${share}%)`;
              }
            }
          }
        }
      }
    });
  }

  function renderTimeline(canvas, series) {
    const palette = tokens();
    destroy('timeline');

    charts.timeline = new Chart(canvas, {
      type: 'line',
      data: {
        labels: series.labels,
        datasets: [
          {
            label: 'Security events',
            data: series.values,
            borderColor: palette.series1,
            backgroundColor: `${palette.series1}22`,
            borderWidth: 2,
            pointRadius: 2,
            pointHoverRadius: 4,
            pointBackgroundColor: palette.series1,
            tension: 0.25,
            fill: true
          }
        ]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: palette.series1, displayColors: false, padding: 8 }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: { precision: 0, color: palette.muted, font: { size: 11 }, padding: 6 },
            grid: { color: palette.grid, drawTicks: false },
            border: { display: false }
          },
          x: {
            ticks: { color: palette.muted, font: { size: 11 }, autoSkip: true, maxRotation: 0, padding: 4 },
            grid: { display: false },
            border: { color: palette.grid }
          }
        }
      }
    });
  }

  /** Draws both charts from the data already in memory. */
  function render() {
    const distributionCanvas = document.getElementById('chart-distribution');
    const timelineCanvas = document.getElementById('chart-timeline');
    if (!data || !distributionCanvas || !timelineCanvas) return;

    renderDistribution(distributionCanvas, data.attackDistribution);
    renderTimeline(timelineCanvas, data.eventsOverTime);
  }

  async function load() {
    const distributionCanvas = document.getElementById('chart-distribution');
    const timelineCanvas = document.getElementById('chart-timeline');
    if (!distributionCanvas || !timelineCanvas || typeof Chart === 'undefined') return;

    try {
      const response = await fetch('/dashboard/data', { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      data = await response.json();
      render();
    } catch (error) {
      showEmpty(distributionCanvas, `Chart data could not be loaded (${error.message}).`);
      showEmpty(timelineCanvas, 'Chart data could not be loaded.');
    }
  }

  function init() {
    load();

    window.addEventListener(
      'themechange',
      () => {
        if (data) window.requestAnimationFrame(render);
      },
      { passive: true }
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

'use strict';

/**
 * Evidence verification (contract §6).
 *
 * The selected file is read as TEXT with FileReader, then posted as JSON with
 * the session CSRF token in a header. The server re-hashes the received text and
 * compares it with the hash recorded for that filename.
 *
 * Server values are written with textContent — never innerHTML — so a payload
 * inside an evidence file cannot inject markup into this page.
 */

(function () {
  const csrfToken = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  };

  const clear = (node) => {
    while (node.firstChild) node.removeChild(node.firstChild);
  };

  /**
   * Renders the outcome.
   * @param {string} message
   * @param {boolean} ok
   * @param {Array<[string, string]>} [rows]
   */
  function render(message, ok, rows) {
    const box = document.getElementById('verify-result');
    if (!box) return;

    clear(box);

    const banner = document.createElement('div');
    banner.className = `ws-banner ws-banner--${ok ? 'success' : 'danger'}`;
    banner.setAttribute('role', 'status');

    const body = document.createElement('div');
    body.className = 'ws-banner__body';
    body.textContent = message;
    banner.appendChild(body);

    box.appendChild(banner);

    if (rows && rows.length) {
      const list = document.createElement('dl');
      list.className = 'ws-kv ws-kv--rows';

      for (const [label, value] of rows) {
        const term = document.createElement('dt');
        term.textContent = label;

        const description = document.createElement('dd');
        description.className = 'ws-mono ws-small ws-break';
        description.textContent = value;

        list.appendChild(term);
        list.appendChild(description);
      }

      box.appendChild(list);
    }
  }

  function readAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error('The file could not be read.'));
      reader.readAsText(file);
    });
  }

  function init() {
    const form = document.getElementById('verify-form');
    if (!form) return;

    form.addEventListener('submit', async (event) => {
      event.preventDefault();

      const input = document.getElementById('evidence-file');
      const button = document.getElementById('verify-submit');
      const file = input && input.files ? input.files[0] : null;

      if (!file) {
        render('Choose an exported evidence file first.', false);
        return;
      }

      button.disabled = true;
      render('Reading the file and recomputing its SHA-256…', true);

      try {
        const content = await readAsText(file);

        const response = await fetch('/forensics/verify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'x-csrf-token': csrfToken()
          },
          body: JSON.stringify({ filename: file.name, content })
        });

        const data = await response.json();

        if (!response.ok) {
          render(data.message || `Verification failed (HTTP ${response.status}).`, false);
          return;
        }

        render(data.message, data.verified, [
          ['File name', data.filename],
          ['Recorded hash', data.expected],
          ['Hash of submitted file', data.actual]
        ]);
      } catch (error) {
        render(`Verification could not be completed: ${error.message}`, false);
      } finally {
        button.disabled = false;
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

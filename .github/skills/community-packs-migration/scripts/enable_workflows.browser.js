// Enables GitHub Actions for repositories: the request behind the button of the Actions tab, which has no REST API.
//
// Run it on a github.com page of a browser session that is signed in as an administrator of the repositories
// (the developer console, or an embedded browser that can run JavaScript in the page). Set `owner` and `repos`.
// It returns at once and keeps going in the background; read the outcome from `window.__enable`:
//   { done: boolean, results: [{ repo, status, body } | { repo, skipped } | { repo, error }] }
//
// A repository that does not show the button is skipped. Disable the workflows it registers right away
// (`default_setup_languages.py disable-workflows`), because the button makes most of them active.
(() => {
  const owner = "OWNER";
  const repos = ["repo-a", "repo-b"];
  const prompts = ["I understand my workflows, go ahead and enable them", "Enable Actions on this repository"];
  const meta = (html, name) => (html.match(new RegExp(`<meta name="${name}" content="([^"]+)"`)) || [])[1];

  window.__enable = { done: false, results: [] };
  (async () => {
    for (const repo of repos) {
      try {
        const base = `/${owner}/${repo}/actions`;
        const page = await fetch(base, { credentials: "same-origin", headers: { Accept: "text/html" } });
        const html = await page.text();
        if (page.status !== 200) { window.__enable.results.push({ repo, error: `page ${page.status}` }); continue; }
        if (!prompts.some((text) => html.includes(text))) { window.__enable.results.push({ repo, skipped: "no enable prompt" }); continue; }
        const response = await fetch(`${base}/enable`, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "GitHub-Verified-Fetch": "true",
            "X-Requested-With": "XMLHttpRequest",
            "X-Fetch-Nonce": meta(html, "fetch-nonce"),
            "X-GitHub-Client-Version": meta(html, "release"),
          },
        });
        window.__enable.results.push({ repo, status: response.status, body: (await response.text()).slice(0, 40) });
      } catch (error) {
        window.__enable.results.push({ repo, error: String(error) });
      }
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    window.__enable.done = true;
  })();
})();

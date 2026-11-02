// Content-script tests. Results are written to <pre id="results"> for
// tests/run-content-tests.sh to read.
(async () => {
  const out = [];
  const ok = (name, cond, extra) => out.push(`${cond ? 'PASS' : 'FAIL'}: ${name}${extra !== undefined && !cond ? ' ' + JSON.stringify(extra) : ''}`);
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  async function waitFor(cond, ms = 2000) {
    for (let t = 0; t < ms; t += 20) { if (cond()) return true; await wait(20); }
    return cond();
  }
  const $ = (id) => document.getElementById(id);
  const scanned = (url) => T.calls.some((c) => c.url === url && c.priority === 'scan');
  const panelTitle = () => (T.shadow && T.shadow.host.isConnected && T.shadow.querySelector('h2')) ? T.shadow.querySelector('h2').textContent : null;
  const panelButton = (label) => T.shadow && [...T.shadow.querySelectorAll('button')].find((b) => b.textContent === label);
  const panelText = () => (T.shadow && T.shadow.host.isConnected) ? T.shadow.textContent : '';

  // Dispatch a click; report whether the extension intercepted it.
  function fire(el, type = 'click', button = 0) {
    const before = T.events.length;
    el.dispatchEvent(new MouseEvent(type, {bubbles: true, cancelable: true, button}));
    const seen = T.events.length > before ? T.events[T.events.length - 1] : null;
    return {intercepted: !seen || seen.prevented};
  }
  function addLink(parent, id, href, text = id) {
    const a = document.createElement('a');
    a.id = id;
    a.href = href;
    a.textContent = text;
    parent.appendChild(document.createElement('p')).appendChild(a);
    return a;
  }

  try {
    // --- Only links in the email are scanned ---
    await waitFor(() => scanned('https://nokey.example/'));
    await wait(200);
    ok('visible links in the email are scanned on load', ['clean', 'bad', 'phish', 'nokey'].every((id) => scanned(`https://${id === 'phish' ? 'evil-login' : id}.example/`)), T.calls);
    ok('a link far down the email is not scanned until it is near the viewport', !scanned('https://far.example/'));
    ok('Gmail interface links are never scanned', !T.calls.some((c) => c.url.includes('ui.example')));
    ok('links into Gmail itself are never scanned', !T.calls.some((c) => !c.url.includes('.example')));

    let r = fire($('ui'));
    ok('a click on a Gmail interface link is not intercepted', !r.intercepted);
    await wait(100);
    ok('a click on a Gmail interface link is not checked either', !T.calls.some((c) => c.url.includes('ui.example')));
    r = fire($('self'));
    ok('a click on a Gmail link is not intercepted', !r.intercepted);

    // --- Marking ---
    ok('malicious link gets a solid outline', $('bad').style.outline.includes('solid'));
    ok('#7 link whose text shows another domain gets a dashed outline', $('phish').style.outline.includes('dashed'), $('phish').style.outline);
    ok('#7 its tooltip explains why', $('phish').title.includes('paypal.com'), $('phish').title);
    ok('clean link is not outlined', $('clean').style.outline === '');

    // --- Clicks and the warning panel ---
    r = fire($('clean'));
    ok('a verified clean link opens normally', !r.intercepted);

    r = fire($('bad'), 'auxclick', 1);
    ok('a middle-click on a malicious link is intercepted', r.intercepted);
    ok('#6 the panel says the link is dangerous', panelTitle() === 'Dangerous link', panelTitle());
    ok('#6 the panel shows the VirusTotal counts', panelText().includes('7 security vendors'));
    panelButton('Open anyway').click();
    ok('#6 "Open anyway" opens the link and closes the panel', T.opened.includes('https://bad.example/') && panelTitle() === null);

    T.opened.length = 0;
    fire($('phish'));
    ok('#6/#7 a misleading link opens a warning panel', panelTitle() === 'This link may be misleading', panelTitle());
    panelButton('Cancel').click();
    ok('#6 Cancel closes the panel without opening anything', panelTitle() === null && T.opened.length === 0);

    fire($('bad'));
    T.shadow.querySelector('.dialog').dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
    ok('#6 Escape closes the panel', panelTitle() === null && T.opened.length === 0);

    fire($('nokey'));
    ok('#6 an unchecked link shows "Checking" first', (panelTitle() || '').startsWith('Checking'), panelTitle());
    await waitFor(() => panelTitle() === 'This link could not be checked');
    ok('#6 a failed check says so', panelTitle() === 'This link could not be checked', panelTitle());
    panelButton('Open settings').click();
    await wait(20);
    ok('#6 "Open settings" asks the background to open the options page', T.openOptions);

    // --- href changes ---
    $('clean').setAttribute('href', 'https://sus.example/');
    r = fire($('clean'));
    ok('a link whose href changed after a clean check is intercepted', r.intercepted);
    await waitFor(() => panelTitle() === 'Suspicious link');
    ok('...and re-checked (suspicious)', panelTitle() === 'Suspicious link', panelTitle());
    panel.close();

    // --- An unchecked clean link clicked before its scan finished ---
    const fresh = addLink($('body1'), 'fresh', 'https://slow-fresh.example/');
    r = fire(fresh);
    ok('a link clicked before its scan finished is intercepted', r.intercepted);
    await waitFor(() => panelTitle() === 'No problems found', 3000);
    ok('#6 a clean result without fresh user activation asks for one more click', panelTitle() === 'No problems found', panelTitle());
    ok('the click check used click priority', T.calls.some((c) => c.url === 'https://slow-fresh.example/' && c.priority === 'click'));
    panelButton('Open link').click();
    ok('#6 "Open link" opens it', T.opened.includes('https://slow-fresh.example/'));

    const forged = addLink($('body1'), 'forged', 'https://bad-forged.example/');
    forged.dataset.vtFlag = 'clean';
    r = fire(forged);
    ok('a forged data-vt-flag="clean" does not bypass interception', r.intercepted);
    panel.close();

    // --- #3 scan on scroll ---
    $('far').scrollIntoView();
    await waitFor(() => scanned('https://far.example/'));
    ok('#3 the far link is scanned once it scrolls into view', scanned('https://far.example/'));
    window.scrollTo(0, 0);

    // --- Popup summary and badge ---
    const summary = await new Promise((resolve) => T.onMessage({type: 'getPageSummary'}, {id: 'test-extension'}, resolve));
    ok('#10 page summary lists flagged links', summary.flagged.some((f) => f.href === 'https://bad.example/') && summary.flagged.some((f) => f.flag === 'misleading'), summary);
    ok('#10 page summary counts message bodies', summary.messageBodies === 1, summary.messageBodies);
    ok('#10 summary is refused for other senders', T.onMessage({type: 'getPageSummary'}, {id: 'someone-else'}, () => {}) === undefined);
    await waitFor(() => T.messages.some((m) => m.type === 'flagCount' && m.count >= 2), 1500);
    ok('#10 flagged count is sent for the badge', T.messages.some((m) => m.type === 'flagCount' && m.count >= 2), T.messages.filter((m) => m.type === 'flagCount'));

    // --- Scan modes ---
    T.peak = 0;
    const later = $('later');
    const spacer = document.createElement('div');
    spacer.style.height = '6000px';
    later.appendChild(spacer);
    const visibleBody = document.createElement('div');
    visibleBody.className = 'a3s';
    document.body.insertBefore(visibleBody, document.body.firstChild);
    for (let i = 0; i < 10; i++) addLink(visibleBody, `v${i}`, `https://visible${i}.example/`);
    await waitFor(() => scanned('https://visible9.example/'), 3000);
    ok('"visible" mode keeps at most 4 scans in flight', T.peak > 0 && T.peak <= 4, T.peak);

    T.onChanged({scanMode: {newValue: 'all'}}, 'sync');
    T.peak = 0;
    const offscreen = document.createElement('div');
    offscreen.className = 'a3s';
    later.appendChild(offscreen);
    for (let i = 0; i < 10; i++) addLink(offscreen, `a${i}`, `https://all${i}.example/`);
    await waitFor(() => scanned('https://all9.example/'), 3000);
    ok('"all" mode scans off-screen links without scrolling', [...Array(10).keys()].every((i) => scanned(`https://all${i}.example/`)));
    ok('"all" mode scans them in parallel', T.peak >= 10, T.peak);

    T.onChanged({scanMode: {newValue: 'click'}}, 'sync');
    addLink(visibleBody, 'c1', 'https://clickmode.example/');
    await wait(500);
    ok('#5 "click" mode does not scan in the background', !scanned('https://clickmode.example/'));
    r = fire($('c1'));
    ok('#5 "click" mode still checks on click', r.intercepted);
    await waitFor(() => T.calls.some((c) => c.url === 'https://clickmode.example/'));
    ok('#5 ...using click priority', T.calls.some((c) => c.url === 'https://clickmode.example/' && c.priority === 'click'));
    panel.close();
  } catch (e) {
    out.push(`FAIL: test script threw ${e && e.stack ? e.stack : e}`);
  }

  const pre = document.createElement('pre');
  pre.id = 'results';
  pre.textContent = out.join('\n') + '\nDONE';
  document.body.appendChild(pre);
})();

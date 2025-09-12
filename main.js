(() => {
window.App = window.App || {};
const AppNS = window.App;

(function init() {
  const { btnConnectSaved, btnClearSession, btnStartUserLogin, btnSubmitPhone, btnSubmitCode, btnSubmitPassword, inpPhone, inpCode, inpPassword, startSearch, sendAll, stopBulk, bulkProgress, bulkLabel, bulkBar, downloadCsv, scrollContainer, status } = AppNS.dom;

  // Wire connect with saved session
  if (btnConnectSaved) btnConnectSaved.addEventListener('click', AppNS.ensureConnected);

  // Clear saved session
  if (btnClearSession) btnClearSession.addEventListener('click', () => {
    try {
      localStorage.clear();
      sessionStorage.clear();
      AppNS.log('Saved session cleared');
      status.textContent = 'idle';
    } catch (e) {
      AppNS.log('Failed to clear storage:', e?.message || e);
    }
  });

  // Start interactive user login
  if (btnStartUserLogin) {
    btnStartUserLogin.addEventListener('click', async () => {
      try {
        status.textContent = 'authorizing…';
        inpPhone.disabled = false; inpCode.disabled = false; inpPassword.disabled = false;
        btnSubmitPhone.disabled = false; btnSubmitCode.disabled = false; btnSubmitPassword.disabled = false;

        btnSubmitPhone.onclick = () => { if (AppNS._resolvePhone) { const v = (inpPhone.value || '').trim(); AppNS.log('Phone submitted'); AppNS._resolvePhone(v); } };
        btnSubmitCode.onclick = () => { if (AppNS._resolveCode) { const v = (inpCode.value || '').trim(); AppNS.log('Code submitted'); AppNS._resolveCode(v); } };
        btnSubmitPassword.onclick = () => { if (AppNS._resolvePassword) { const v = inpPassword.value || ''; AppNS.log('Password submitted'); AppNS._resolvePassword(v); } };

        await AppNS.client.start({ phoneNumber: AppNS.phoneNumber, phoneCode: AppNS.phoneCode, password: AppNS.password, onError: (e) => AppNS.log('Auth error:', e?.message || e) });
        AppNS.resetResolvers();
        await AppNS.ensureConnected();
        AppNS.log('Authorization completed');
      } catch (err) {
        AppNS.resetResolvers();
        AppNS.client.disconnect();
        status.textContent = 'idle';
        AppNS.log('User login failed:', err?.message || String(err));
      }
    });
  }

  // Search
  if (startSearch) startSearch.addEventListener('click', async () => {
    const connected = await AppNS.ensureConnected();
    if (!connected) { AppNS.log('Please authenticate using your existing flow, then retry.'); return; }
    const st = AppNS.searchState;
    st.currentQuery = AppNS.dom.query.value || '';
    st.useHashtag = !!AppNS.dom.hashtag.checked;
    st.targetDisplayLimit = Math.max(10, Math.min(5000, Number(AppNS.dom.limit.value) || 1000));
    AppNS.resetResults();
    while (!st.finished && st.loadedCount < st.targetDisplayLimit) {
      await AppNS.loadNextPage();
      await new Promise(r => setTimeout(r));
    }
  });

  // Infinite scroll
  if (scrollContainer) scrollContainer.addEventListener('scroll', async () => {
    const nearBottom = scrollContainer.scrollTop + scrollContainer.clientHeight >= scrollContainer.scrollHeight - 200;
    if (nearBottom) await AppNS.loadNextPage();
  });

  // Bulk send
  if (stopBulk) stopBulk.addEventListener('click', () => { AppNS.searchState.bulkCancelRequested = true; AppNS.log('Bulk cancel requested'); });

  if (sendAll) sendAll.addEventListener('click', async () => {
    try {
      const rows = AppNS.collectRows();
      if (!rows.length) { alert('No rows to send'); return; }
      bulkProgress.style.display = '';
      bulkLabel.style.display = '';
      const update = (done, total) => { const pct = total ? Math.round((done / total) * 100) : 0; bulkBar.style.width = pct + '%'; bulkLabel.textContent = `${done} / ${total}`; };
      update(0, rows.length);
      let sent = 0;
      AppNS.searchState.bulkCancelRequested = false;
      for (const { tr } of rows) {
        if (AppNS.searchState.bulkCancelRequested) { AppNS.log('Bulk send stopped by user'); break; }
        try { await AppNS.sendCommentForDataset(tr.dataset); } catch (e) { AppNS.log('Bulk send error:', e?.message || e); }
        sent += 1; update(sent, rows.length); await new Promise(r => setTimeout(r, 1000));
      }
      AppNS.log('Bulk send finished:', `${rows.length} attempted`);
    } catch (e) {
      AppNS.log('Bulk send failed:', e?.message || e);
    }
  });

  // CSV download
  if (downloadCsv) downloadCsv.addEventListener('click', () => {
    try {
      const csv = AppNS.tableToCsv();
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      a.download = `results-${ts}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      AppNS.log('CSV download failed:', e?.message || e);
    }
  });

  // Auto-connect on load
  (async () => { await AppNS.ensureConnected(); })();
})();
})();



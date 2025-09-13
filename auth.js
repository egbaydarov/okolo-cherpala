(() => {
  window.App = window.App || {};
  const AppNS = window.App;
  const telegram = AppNS.telegram;

  // Session persistence
  AppNS.getExistingSessionData = function getExistingSessionData() {
    try {
      const raw = localStorage.getItem(AppNS.config.sessionStorageKey);
      return raw ? JSON.parse(raw) : undefined;
    } catch (_) { return undefined; }
  };

  AppNS.onSessionUpdate = function onSessionUpdate(sessionData) {
    try {
      if (!sessionData) {
        localStorage.removeItem(AppNS.config.sessionStorageKey);
        return;
      }
      const toStore = { ...sessionData, dcId: sessionData.mainDcId };
      localStorage.setItem(AppNS.config.sessionStorageKey, JSON.stringify(toStore));
    } catch (_) {}
  };

  // Telegram client lifecycle
  AppNS.session = new telegram.sessions.CallbackSession(AppNS.getExistingSessionData(), AppNS.onSessionUpdate);
  AppNS.session.setDC(2);
  AppNS.client = new telegram.TelegramClient(
    AppNS.session,
    AppNS.config.apiId,
    AppNS.config.apiHash,
    {
      requestRetries: 1,
      connectionRetries: 2,
      useWSS: true
    }
  );

  AppNS.ensureConnected = async function ensureConnected() {
    const { status } = AppNS.dom;
    try {
      status.textContent = 'connecting…';
      await AppNS.client.connect({});
      try {
        const me = await AppNS.client.invoke(new telegram.Api.users.GetFullUser({ id: new telegram.Api.InputUserSelf() }));
        AppNS.updateAccountUI(me);
        status.textContent = 'connected';
        return true;
      } catch (authErr) {
        AppNS.client.disconnect();
        status.textContent = 'not authorized';
        return false;
      }
    } catch (e) {
      AppNS.client.disconnect();
      status.textContent = 'not authorized';
      AppNS.log('Connect failed (probably no saved session):', e?.message || e);
      return false;
    }
  };

  // Interactive auth resolvers
  AppNS._resolvePhone = null;
  AppNS._resolveCode = null;
  AppNS._resolvePassword = null;

  AppNS.phoneNumber = () => new Promise((resolve) => { AppNS._resolvePhone = resolve; });
  AppNS.phoneCode = () => new Promise((resolve) => { AppNS._resolveCode = resolve; });
  AppNS.password = () => new Promise((resolve) => { AppNS._resolvePassword = resolve; });
  AppNS.resetResolvers = function resetResolvers() { AppNS._resolvePhone = null; AppNS._resolveCode = null; AppNS._resolvePassword = null; };
})();



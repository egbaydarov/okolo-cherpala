(() => {
  // Global app namespace and shared state (procedural style)
  window.App = window.App || {};
  const App = window.App;

  // External Telegram library (loaded by tg-min.js)
  App.telegram = window.GramJs;

  // Configuration (keep separate from UI/auth logic)
  App.config = {
    apiId: 20420825,
    apiHash: "ee1672f1a070db396378556012f0aeda",
    sessionStorageKey: "account1"
  };

  // DOM references
  App.dom = {
    status: document.getElementById('status'),
    log: document.getElementById('log'),
    meName: document.getElementById('meName'),
    meBio: document.getElementById('meBio'),
    meAvatar: document.getElementById('meAvatar'),

    btnConnectSaved: document.getElementById('connectSaved'),
    btnClearSession: document.getElementById('clearSession'),
    btnStartUserLogin: document.getElementById('startUserLogin'),
    btnSubmitPhone: document.getElementById('submitPhone'),
    btnSubmitCode: document.getElementById('submitCode'),
    btnSubmitPassword: document.getElementById('submitPassword'),

    inpPhone: document.getElementById('phone'),
    inpCode: document.getElementById('code'),
    inpPassword: document.getElementById('password'),

    rows: document.getElementById('rows'),
    loading: document.getElementById('loading'),
    end: document.getElementById('endOfList'),
    query: document.getElementById('searchQuery'),
    limit: document.getElementById('displayLimit'),
    hashtag: document.getElementById('hashtagMode'),
    commentText: document.getElementById('commentText'),
    startSearch: document.getElementById('startSearch'),
    sendAll: document.getElementById('sendAll'),
    stopBulk: document.getElementById('stopBulk'),
    bulkProgress: document.getElementById('bulkProgress'),
    bulkBar: document.getElementById('bulkBar'),
    bulkLabel: document.getElementById('bulkLabel'),
    downloadCsv: document.getElementById('downloadCsv'),
    scrollContainer: document.querySelector('fieldset:last-of-type > div[style*="overflow:auto"]')
  };

  // Runtime search state
  App.searchState = {
    nextRate: 0,
    offsetIdOffset: 0,
    prevNextRate: -1,
    prevOffsetIdOffset: -1,
    noProgressStreak: 0,
    loading: false,
    finished: false,
    loadedCount: 0,
    currentQuery: '',
    useHashtag: false,
    targetDisplayLimit: 1000,
    channelIndex: new Map(),
    seenMessageKeys: new Set(),
    bulkCancelRequested: false
  };
})();



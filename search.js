(() => {
window.App = window.App || {};
const AppNS = window.App;
const telegram = AppNS.telegram;

AppNS.upsertChannels = function upsertChannels(chats) {
  const st = AppNS.searchState;
  if (!Array.isArray(chats)) return;
  for (const ch of chats) {
    const id = ch?.id ?? ch?.channelId ?? ch?.channel_id;
    if (id == null) continue;
    const key = AppNS.bigIntToStringSafe(id);
    st.channelIndex.set(key, {
      id: id,
      accessHash: ch?.accessHash ?? ch?.access_hash,
      username: ch?.username,
      title: ch?.title
    });
  }
};

AppNS.getChannelFromPeerId = function getChannelFromPeerId(peerId) {
  if (!peerId) return null;
  const chId = peerId?.channelId ?? peerId?.channel_id;
  if (chId == null) return null;
  const key = AppNS.bigIntToStringSafe(chId);
  return AppNS.searchState.channelIndex.get(key) || null;
};

// Check search flood status and return a normalized object
AppNS.checkSearchPostsFlood = async function checkSearchPostsFlood(query) {
  try {
    const res = await AppNS.client.invoke(new telegram.Api.channels.CheckSearchPostsFlood({ query }));
    if (!res) return null;
    return {
      query,
      queryIsFree: !!res.queryIsFree,
      totalDaily: res.totalDaily,
      remains: res.remains,
      waitTill: res.waitTill,
      starsAmount: Number(res.starsAmount?.toJSNumber?.() ?? res.starsAmount ?? 0)
    };
  } catch (e) {
    // If API not available on server, treat as no flood info
    return null;
  }
};

AppNS.appendRows = function appendRows(messages) {
  const st = AppNS.searchState;
  const { rows } = AppNS.dom;
  const frag = document.createDocumentFragment();
  let added = 0;
  // Precompute thresholds for stats
  const now = Math.floor(Date.now() / 1000);
  const dayAgo = now - 24 * 3600;
  const weekAgo = now - 7 * 24 * 3600;
  const monthAgo = Math.floor(new Date(new Date().setUTCMonth(new Date().getUTCMonth() - 1)).getTime() / 1000);
  const yearAgo = Math.floor(new Date(new Date().setUTCFullYear(new Date().getUTCFullYear() - 1)).getTime() / 1000);
  for (const m of messages) {
    if (!m || m.className !== 'Message') continue;
    const channel = AppNS.getChannelFromPeerId(m.peerId);
    const chId = m?.peerId?.channelId ?? m?.peerId?.channel_id;
    if (chId != null) {
      const key = `${AppNS.bigIntToStringSafe(chId)}:${m.id}`;
      if (st.seenMessageKeys.has(key)) continue;
      st.seenMessageKeys.add(key);
      // Only show the first message per channel
      const chKey = AppNS.bigIntToStringSafe(chId);
      if (st.displayedChannelIds.has(chKey)) {
        continue;
      }
      st.displayedChannelIds.add(chKey);
    }
    const tr = document.createElement('tr');
    const deepLink = (channel?.username ? `https://t.me/${channel.username}/${m.id}` : `tg://openmessage?chat_id=-100${AppNS.bigIntToStringSafe(channel?.id || '')}&message_id=${m.id}`);
    const webLink = `https://web.telegram.org/a/#?tgaddr=${encodeURIComponent(deepLink)}`;
    tr.innerHTML = `
      <td style="padding:8px; border-bottom:1px solid #eee;">${channel?.title || channel?.username || 'Unknown channel'}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;">${m.id}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;">${AppNS.formatDate(m.date)}</td>
      <td style=\"padding:8px; border-bottom:1px solid #eee; max-width:480px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;\" title=\"${(m.message || '').replace(/\"/g, '\\\"')}\">${(m.message || '').slice(0, 160)}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;"><a href="${deepLink}" target="_blank" rel="noopener">Open</a></td>
      <td style="padding:8px; border-bottom:1px solid #eee;"><a href="${webLink}" target="_blank" rel="noopener">Web</a></td>
      <td style="padding:8px; border-bottom:1px solid #eee;"><button class="commentBtn">Comment</button></td>
    `;
    tr.dataset.channelId = channel?.id ? AppNS.bigIntToStringSafe(channel.id) : '';
    tr.dataset.accessHash = channel?.accessHash ? AppNS.bigIntToStringSafe(channel.accessHash) : '';
    tr.dataset.username = channel?.username || '';
    tr.dataset.title = channel?.title || '';
    tr.dataset.postId = String(m.id);
    if (m.replies?.channelId) tr.dataset.discussionChannelId = AppNS.bigIntToStringSafe(m.replies.channelId);
    // Async check membership and color row
    try {
      const chKey = tr.dataset.channelId;
      if (chKey && !AppNS.membershipStatus.has(chKey) && !AppNS.membershipPending.has(chKey)) {
        AppNS.membershipPending.add(chKey);
        (async () => {
          let status = 'not';
          try {
            const chIdBig = AppNS.toBigIntSafe(chKey);
            const peer = new telegram.Api.InputPeerChannel({ channelId: chIdBig, accessHash: AppNS.toBigIntSafe(tr.dataset.accessHash) });
            const info = await AppNS.client.invoke(new telegram.Api.channels.GetParticipant({ channel: peer, participant: new telegram.Api.InputPeerSelf() }));
            const p = info?.participant;
            if (p && (p.className?.includes('ChannelParticipant') || p.className === 'ChannelParticipantSelf')) status = 'member';
          } catch (e) {
            const msg = String(e?.message || e);
            if (/USER_BANNED|BANNED|KICKED/i.test(msg)) status = 'banned';
          }
          AppNS.membershipStatus.set(chKey, status);
          AppNS.membershipPending.delete(chKey);
          // apply light colors
          if (status === 'member') { tr.style.background = '#e9f7ef'; }
          else if (status === 'banned') { tr.style.background = '#fdecea'; }
          else { tr.style.background = '#fffbe6'; }
        })();
      } else if (chKey) {
        const status = AppNS.membershipStatus.get(chKey);
        if (status === 'member') { tr.style.background = '#e9f7ef'; }
        else if (status === 'banned') { tr.style.background = '#fdecea'; }
        else if (status === 'not') { tr.style.background = '#fffbe6'; }
      }
    } catch (_) {}
    const btn = tr.querySelector('.commentBtn');
    btn.addEventListener('click', async () => {
      try {
        await AppNS.sendCommentForDataset(tr.dataset);
        const link = tr.querySelector('a')?.href || (channel?.username ? `https://t.me/${channel.username}/${m.id}` : `tg://openmessage?chat_id=-100${AppNS.bigIntToStringSafe(channel?.id || '')}&message_id=${m.id}`);
        AppNS.log('Comment sent:', link);
      } catch (e) {
        AppNS.log('Failed to send comment:', e?.message || String(e));
      }
    });
    frag.appendChild(tr);
    st.loadedCount += 1;
    added += 1;
    // Update stats
    st.stats.total += 1;
    const ts = m.date || 0;
    if (ts >= dayAgo) st.stats.today += 1;
    if (ts >= weekAgo) st.stats.week += 1;
    if (ts >= monthAgo) st.stats.month += 1;
    if (ts >= yearAgo) st.stats.year += 1;
  }
  rows.appendChild(frag);
  AppNS.updateStats();
  return added;
};

AppNS.resetResults = function resetResults() {
  const st = AppNS.searchState;
  const { rows, loading, end } = AppNS.dom;
  rows.innerHTML = '';
  st.nextRate = 0; st.loading = false; st.finished = false; st.loadedCount = 0; st.seenMessageKeys.clear();
  loading.style.display = 'none'; end.style.display = 'none';
  // Reset stats
  st.stats.total = 0; st.stats.today = 0; st.stats.week = 0; st.stats.month = 0; st.stats.year = 0;
  AppNS.updateStats();
};

AppNS.loadNextPage = async function loadNextPage() {
  const st = AppNS.searchState;
  const { loading, end } = AppNS.dom;
  if (st.loading || st.finished) return;
  if (st.loadedCount >= st.targetDisplayLimit) return;
  st.loading = true; loading.style.display = '';
  try {
    const query = st.currentQuery.trim();

    // Check flood limits before searching
    let allowPaidStars = 0n;
    const flood = await AppNS.checkSearchPostsFlood(query);
    if (flood) { st.searchFlood = flood; allowPaidStars = BigInt(flood.starsAmount || 0); }

    const req = new telegram.Api.channels.SearchPosts({
      hashtag: st.useHashtag ? query : "",
      query: st.useHashtag ? "" : query,
      offsetRate: st.nextRate || 0,
      offsetPeer: new telegram.Api.InputPeerEmpty(),
      offsetId: st.offsetIdOffset || 0,
      limit: st.targetDisplayLimit ?? 100,
      allowPaidStars
    });
    const res = await AppNS.client.invoke(req);
    AppNS.upsertChannels(res?.chats || []);
    const allMsgs = Array.isArray(res?.messages) ? res.messages : [];
    // Filter by date range if provided
    let filtered = allMsgs;
    const fromTs = AppNS.searchState.fromTs;
    const toTs = AppNS.searchState.toTs;
    if (fromTs != null || toTs != null) {
      filtered = allMsgs.filter(m => {
        const ts = m?.date || 0;
        if (fromTs != null && ts < fromTs) return false;
        if (toTs != null && ts > toTs) return false;
        return true;
      });
    }
    const added = AppNS.appendRows(filtered);
    st.nextRate = res?.nextRate || 0;
    st.offsetIdOffset = res?.offsetIdOffset || 0;
    if ((st.prevNextRate === st.nextRate && st.prevOffsetIdOffset === st.offsetIdOffset) || added === 0) {
      st.noProgressStreak += 1;
    } else {
      st.noProgressStreak = 0;
    }
    st.prevNextRate = st.nextRate; st.prevOffsetIdOffset = st.offsetIdOffset;
    // Stop if no more results or we've paged past the lower date bound
    const oldestMsg = allMsgs[allMsgs.length - 1];
    const reachedLowerBound = oldestMsg && fromTs != null ? (oldestMsg.date < fromTs) : false;
    if ((allMsgs.length === 0) || reachedLowerBound || (!st.nextRate && !st.offsetIdOffset) || st.noProgressStreak >= 2) {
      st.finished = true;
      end.style.display = '';
    }
  } catch (e) {
    AppNS.log('Search error:', e?.message || e);
    st.finished = true; end.style.display = '';
  } finally {
    st.loading = false; loading.style.display = 'none';
  }
};

AppNS.collectRows = function collectRows() {
  const trs = AppNS.dom.rows.querySelectorAll('tr');
  const list = [];
  for (const tr of trs) {
    const idCell = tr.children[1]?.textContent?.trim();
    const linkCell = tr.children[4]?.querySelector('a');
    const actionBtn = tr.querySelector('.commentBtn');
    if (!idCell || !linkCell || !actionBtn) continue;
    list.push({ tr, id: Number(idCell), actionBtn });
  }
  return list;
};
})();



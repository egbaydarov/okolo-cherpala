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

AppNS.appendRows = function appendRows(messages) {
  const st = AppNS.searchState;
  const { rows } = AppNS.dom;
  const frag = document.createDocumentFragment();
  let added = 0;
  for (const m of messages) {
    if (!m || m.className !== 'Message') continue;
    const channel = AppNS.getChannelFromPeerId(m.peerId);
    const chId = m?.peerId?.channelId ?? m?.peerId?.channel_id;
    if (chId != null) {
      const key = `${AppNS.bigIntToStringSafe(chId)}:${m.id}`;
      if (st.seenMessageKeys.has(key)) continue;
      st.seenMessageKeys.add(key);
    }
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="padding:8px; border-bottom:1px solid #eee;">${channel?.title || channel?.username || 'Unknown channel'}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;">${m.id}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;">${AppNS.formatDate(m.date)}</td>
      <td style=\"padding:8px; border-bottom:1px solid #eee; max-width:480px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;\" title=\"${(m.message || '').replace(/\"/g, '\\\"')}\">${(m.message || '').slice(0, 160)}</td>
      <td style="padding:8px; border-bottom:1px solid #eee;"><a href="${(channel?.username ? `https://t.me/${channel.username}/${m.id}` : `tg://openmessage?chat_id=-100${AppNS.bigIntToStringSafe(channel?.id || '')}&message_id=${m.id}`)}" target="_blank" rel="noopener">Open</a></td>
      <td style="padding:8px; border-bottom:1px solid #eee;"><button class="commentBtn">Comment</button></td>
    `;
    tr.dataset.channelId = channel?.id ? AppNS.bigIntToStringSafe(channel.id) : '';
    tr.dataset.accessHash = channel?.accessHash ? AppNS.bigIntToStringSafe(channel.accessHash) : '';
    tr.dataset.username = channel?.username || '';
    tr.dataset.title = channel?.title || '';
    tr.dataset.postId = String(m.id);
    if (m.replies?.channelId) tr.dataset.discussionChannelId = AppNS.bigIntToStringSafe(m.replies.channelId);
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
  }
  rows.appendChild(frag);
  return added;
};

AppNS.resetResults = function resetResults() {
  const st = AppNS.searchState;
  const { rows, loading, end } = AppNS.dom;
  rows.innerHTML = '';
  st.nextRate = 0; st.loading = false; st.finished = false; st.loadedCount = 0; st.seenMessageKeys.clear();
  loading.style.display = 'none'; end.style.display = 'none';
};

AppNS.loadNextPage = async function loadNextPage() {
  const st = AppNS.searchState;
  const { loading, end } = AppNS.dom;
  if (st.loading || st.finished) return;
  if (st.loadedCount >= st.targetDisplayLimit) return;
  st.loading = true; loading.style.display = '';
  try {
    const query = st.currentQuery.trim();
    const req = new telegram.Api.channels.SearchPosts({
      hashtag: st.useHashtag ? query : "",
      query: st.useHashtag ? "" : query,
      offsetRate: st.nextRate || 0,
      offsetPeer: new telegram.Api.InputPeerEmpty(),
      offsetId: st.offsetIdOffset || 0,
      limit: 1000
    });
    const res = await AppNS.client.invoke(req);
    AppNS.upsertChannels(res?.chats || []);
    const msgs = Array.isArray(res?.messages) ? res.messages : [];
    const added = AppNS.appendRows(msgs);
    st.nextRate = res?.nextRate || 0;
    st.offsetIdOffset = res?.offsetIdOffset || 0;
    if ((st.prevNextRate === st.nextRate && st.prevOffsetIdOffset === st.offsetIdOffset) || added === 0) {
      st.noProgressStreak += 1;
    } else {
      st.noProgressStreak = 0;
    }
    st.prevNextRate = st.nextRate; st.prevOffsetIdOffset = st.offsetIdOffset;
    if ((msgs.length === 0) || (!st.nextRate && !st.offsetIdOffset) || st.noProgressStreak >= 2) {
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



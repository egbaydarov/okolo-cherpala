(() => {
  window.App = window.App || {};
  const AppNS = window.App;
  const telegram = AppNS.telegram;

  // removed web-based send attempt per user request

  AppNS.sendCommentForDataset = async function sendCommentForDataset(ds) {
    const text = (AppNS.dom.commentText.value || '').trim();
    if (!text) throw new Error('Set comment text in Settings');
    const original = { id: ds.channelId, accessHash: ds.accessHash, username: ds.username, title: ds.title };
    const link = (ds.username ? `https://t.me/${ds.username}/${ds.postId}` : `tg://openmessage?chat_id=-100${ds.channelId}&message_id=${ds.postId}`);
    AppNS.log('Sending comment:', link);

    const postIdNum = Number(ds.postId);
    let lastErr = null;

    // 1) Reply in discussion chat first (threaded comment under post)
    try {
      let discussion = await AppNS.resolveDiscussionPeer(original, postIdNum);
      if (!discussion) discussion = await AppNS.getLinkedDiscussionPeer(original);
      if (!discussion?.id || !discussion?.accessHash) throw new Error('No discussion chat available');
      const dIdBig = AppNS.toBigIntSafe(discussion.id);
      const dHashBig = AppNS.toBigIntSafe(discussion.accessHash);
      if (!dIdBig || !dHashBig) throw new Error('Invalid discussion identifiers');
      try {
        const inputCh = new telegram.Api.InputChannel({ channelId: dIdBig, accessHash: dHashBig });
        await AppNS.client.invoke(new telegram.Api.channels.JoinChannel({ channel: inputCh }));
      } catch (_) {}
      const peer = new telegram.Api.InputPeerChannel({ channelId: dIdBig, accessHash: dHashBig });
      const randomId = AppNS.generateRandomBigInt64();
      const topIdForDiscussion = Number(discussion.topMsgId || postIdNum);
      const replyTo = new telegram.Api.InputReplyToMessage({ replyToMsgId: topIdForDiscussion, topMsgId: topIdForDiscussion });
      const req = new telegram.Api.messages.SendMessage({ peer, message: text, replyTo, randomId, updateStickersetsOrder: true });
      await AppNS.client.invoke(req);
      return;
    } catch (e) {
      lastErr = e;
      AppNS.log('Discussion reply failed:', e?.message || String(e));
    }

    // 2) Fallback: direct reply to original channel
    try {
      const chIdBig = AppNS.toBigIntSafe(original.id);
      const hashBig = AppNS.toBigIntSafe(original.accessHash);
      if (!chIdBig || !hashBig) throw new Error('Invalid channel identifiers');
      try {
        const inputCh = new telegram.Api.InputChannel({ channelId: chIdBig, accessHash: hashBig });
        await AppNS.client.invoke(new telegram.Api.channels.JoinChannel({ channel: inputCh }));
      } catch (_) {}
      const peer = new telegram.Api.InputPeerChannel({ channelId: chIdBig, accessHash: hashBig });
      const randomId = AppNS.generateRandomBigInt64();
      const replyTo = new telegram.Api.InputReplyToMessage({ replyToMsgId: postIdNum, topMsgId: postIdNum });
      const req = new telegram.Api.messages.SendMessage({ peer, message: text, replyTo, randomId, updateStickersetsOrder: true });
      await AppNS.client.invoke(req);
      return;
    } catch (e2) {
      lastErr = e2;
      AppNS.log('Direct reply failed:', e2?.message || String(e2));
    }

    if (lastErr) throw lastErr;
  };

  AppNS.resolveDiscussionPeer = async function resolveDiscussionPeer(original, postId) {
    try {
      const chIdBig = AppNS.toBigIntSafe(original.id);
      const hashBig = AppNS.toBigIntSafe(original.accessHash);
      if (!chIdBig || !hashBig) return undefined;
      const originPeer = new telegram.Api.InputPeerChannel({ channelId: chIdBig, accessHash: hashBig });
      const res = await AppNS.client.invoke(new telegram.Api.messages.GetDiscussionMessage({ peer: originPeer, msgId: postId }));
      const chats = res?.chats || [];
      let candidate = undefined;
      let discussionTopId = undefined;
      for (const chat of chats) {
        if (chat?.className === 'Channel' && chat?.megagroup && AppNS.bigIntToStringSafe(chat.id) !== AppNS.bigIntToStringSafe(original.id)) {
          candidate = chat;
          break;
        }
      }
      if (!candidate && Array.isArray(res?.messages)) {
        for (const msg of res.messages) {
          const p = msg?.peerId;
          if (p?.channelId) {
            const key = AppNS.bigIntToStringSafe(p.channelId);
            const fallback = chats.find(c => AppNS.bigIntToStringSafe(c.id) === key);
            if (fallback?.megagroup && AppNS.bigIntToStringSafe(fallback.id) !== AppNS.bigIntToStringSafe(original.id)) {
              candidate = fallback;
              // try map top id in discussion
              discussionTopId = Number(msg?.id || msg?.replyTo?.replyToTopId || postId);
              break;
            }
          }
        }
      }
      if (!candidate) return undefined;
      // If not found from messages loop, try to infer from any message whose peer matches candidate
      if (!discussionTopId && Array.isArray(res?.messages)) {
        const m2 = res.messages.find(m => AppNS.bigIntToStringSafe(m?.peerId?.channelId) === AppNS.bigIntToStringSafe(candidate.id));
        if (m2?.id) discussionTopId = Number(m2.id);
      }
      return { id: candidate.id, accessHash: candidate.accessHash, username: candidate.username, title: candidate.title, topMsgId: discussionTopId };
    } catch (_) {
      return undefined;
    }
  };

  AppNS.getLinkedDiscussionPeer = async function getLinkedDiscussionPeer(original) {
    try {
      const chIdBig = AppNS.toBigIntSafe(original.id);
      const hashBig = AppNS.toBigIntSafe(original.accessHash);
      if (!chIdBig || !hashBig) return undefined;
      const inputCh = new telegram.Api.InputChannel({ channelId: chIdBig, accessHash: hashBig });
      const res = await AppNS.client.invoke(new telegram.Api.channels.GetFullChannel({ channel: inputCh }));
      const full = res?.fullChat;
      const linkedId = full?.linkedChatId || full?.linked_chat_id;
      if (!linkedId) return undefined;
      const chats = res?.chats || [];
      const candidate = chats.find(c => AppNS.bigIntToStringSafe(c.id) === AppNS.bigIntToStringSafe(linkedId));
      if (!candidate) return undefined;
      return { id: candidate.id, accessHash: candidate.accessHash, username: candidate.username, title: candidate.title };
    } catch (_) {
      return undefined;
    }
  };
})();



(() => {
  window.App = window.App || {};
  const AppNS = window.App;
  const telegram = AppNS.telegram;

  AppNS.updateAccountUI = function updateAccountUI(meFull) {
    const { meName, meBio, meAvatar } = AppNS.dom;
    try {
      const user = meFull?.fullUser?.about !== undefined ? meFull.users?.find?.(u => u?.self) || meFull.users?.[0] : meFull?.user || meFull;
      const about = meFull?.fullUser?.about || '';
      const name = user ? [user.firstName, user.lastName].filter(Boolean).join(' ') || user.username || 'Me' : 'Me';
      meName.textContent = name;
      meBio.textContent = about;
      (async () => {
        try {
          const photos = await AppNS.client.invoke(new telegram.Api.photos.GetUserPhotos({ userId: new telegram.Api.InputUserSelf(), offset: 0, maxId: 0, limit: 1 }));
          const first = photos?.photos?.[0];
          if (first && first.className === 'Photo') {
            const loc = new telegram.Api.InputPhotoFileLocation({ id: first.id, accessHash: first.accessHash, fileReference: first.fileReference, thumbSize: 'a' });
            const bytes = await AppNS.client.downloadFile(loc, { dcId: first.dcId || undefined, fileSize: 0, partSizeKb: 64, workers: 1 });
            if (bytes) {
              const blob = new Blob([bytes], { type: 'image/jpeg' });
              const url = URL.createObjectURL(blob);
              meAvatar.style.backgroundImage = `url(${url})`;
              meAvatar.style.backgroundSize = 'cover';
              meAvatar.style.backgroundPosition = 'center';
            }
          }
        } catch (_) {}
      })();
    } catch (_) {}
  };
})();



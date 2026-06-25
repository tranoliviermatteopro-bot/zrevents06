(async () => {
  try {
    const r = await fetch('/api/settings');
    if (!r.ok) return;
    const s = await r.json();
    if (s.site_nom) {
      document.querySelectorAll('[data-site-nom]').forEach(el => { el.textContent = s.site_nom; });
      if (document.title) document.title = document.title.replace(/zrevents06/gi, s.site_nom);
    }
    if (s.site_sous_titre) {
      document.querySelectorAll('[data-site-sous-titre]').forEach(el => { el.textContent = s.site_sous_titre; });
    }
    if (s.contact_email) {
      document.querySelectorAll('[data-site-email]').forEach(el => {
        el.textContent = s.contact_email;
        if (el.tagName === 'A') el.href = 'mailto:' + s.contact_email;
      });
    }
  } catch {}
})();

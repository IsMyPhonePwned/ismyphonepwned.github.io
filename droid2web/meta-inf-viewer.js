/**
 * Structured viewer for APK v1 signing files (MANIFEST.MF, *.SF, *.RSA|*.DSA|*.EC).
 */

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(s) {
  return escHtml(s).replace(/'/g, '&#39;');
}

function infoRow(label, value, opts = {}) {
  if (value == null || value === '') return '';
  const mono = opts.mono ? ' info-mono' : '';
  const title = opts.title ? ` title="${escAttr(opts.title)}"` : '';
  return `<div class="info-row"${title}><span class="info-label">${escHtml(label)}</span><span class="info-value${mono}">${escHtml(String(value))}</span></div>`;
}

function certBlock(cert, index) {
  const bits = [
    infoRow('Subject', cert.subject),
    infoRow('Issuer', cert.issuer),
    infoRow('Serial', cert.serial_number),
    infoRow('Valid', [cert.not_before, cert.not_after].filter(Boolean).join(' → ')),
    infoRow('Sig alg', cert.signature_algorithm),
    infoRow('Key', [cert.public_key_algorithm, cert.public_key_size != null ? `${cert.public_key_size}-bit` : null].filter(Boolean).join(' ')),
    infoRow('SHA-1', cert.sha1, { mono: true }),
    infoRow('SHA-256', cert.sha256, { mono: true }),
  ].join('');
  return `<div class="info-cert meta-inf-cert"><div class="info-section">Certificate ${index + 1}</div>${bits}</div>`;
}

function digestAttrName(attrs) {
  return attrs.find((a) => /-Digest$/i.test(a.name))?.name || 'Digest';
}

function renderManifestSections(sections, filter = '') {
  const q = filter.trim().toLowerCase();
  const main = sections[0];
  const named = sections.slice(1).filter((s) => s.name);
  const filtered = q
    ? named.filter((s) => {
        const hay = `${s.name || ''} ${(s.attributes || []).map((a) => `${a.name} ${a.value}`).join(' ')}`.toLowerCase();
        return hay.includes(q);
      })
    : named;

  let html = '';
  if (main?.attributes?.length) {
    html += '<div class="meta-inf-section"><div class="meta-inf-section-title">Main attributes</div><table class="meta-inf-attr-table"><tbody>';
    for (const attr of main.attributes) {
      if (attr.name.toLowerCase() === 'name') continue;
      html += `<tr><th>${escHtml(attr.name)}</th><td class="info-mono">${escHtml(attr.value)}</td></tr>`;
    }
    html += '</tbody></table></div>';
  }

  html += `<div class="meta-inf-section"><div class="meta-inf-section-title">Signed entries <span class="muted">(${filtered.length}${q ? ` / ${named.length}` : ''})</span></div>`;
  if (!filtered.length) {
    html += `<div class="muted meta-inf-empty">${q ? 'No entries match filter.' : 'No named entries.'}</div>`;
  } else {
    html += '<div class="meta-inf-entry-list">';
    for (const section of filtered) {
      const digest = section.attributes.find((a) => /-Digest$/i.test(a.name));
      html += `<details class="meta-inf-entry"${filtered.length <= 12 ? ' open' : ''}>`;
      html += `<summary><span class="meta-inf-entry-name">${escHtml(section.name || '(unnamed)')}</span>`;
      if (digest) {
        html += `<span class="meta-inf-entry-digest muted">${escHtml(digest.name)}</span>`;
      }
      html += '</summary>';
      if (digest) {
        html += `<div class="meta-inf-digest info-mono">${escHtml(digest.value)}</div>`;
      }
      const rest = section.attributes.filter((a) => a !== digest && a.name.toLowerCase() !== 'name');
      if (rest.length) {
        html += '<table class="meta-inf-attr-table compact"><tbody>';
        for (const attr of rest) {
          html += `<tr><th>${escHtml(attr.name)}</th><td class="info-mono">${escHtml(attr.value)}</td></tr>`;
        }
        html += '</tbody></table>';
      }
      html += '</details>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

function toolbarChips(data, name) {
  const chips = [];
  if (data.kind === 'manifest') {
    chips.push(`<span class="res-chip">MANIFEST.MF</span>`);
    chips.push(`<span class="res-chip">${data.entry_count ?? 0} entries</span>`);
  } else if (data.kind === 'signature') {
    chips.push(`<span class="res-chip">Signature (.SF)</span>`);
    chips.push(`<span class="res-chip">${data.entry_count ?? 0} entries</span>`);
    if (data.digest_algorithm) chips.push(`<span class="res-chip">${escHtml(data.digest_algorithm)}</span>`);
  } else if (data.kind === 'pkcs7') {
    chips.push(`<span class="res-chip">PKCS#7 · ${escHtml(data.format || 'RSA')}</span>`);
    chips.push(`<span class="res-chip">${(data.certificates || []).length} cert(s)</span>`);
  } else {
    chips.push(`<span class="res-chip">META-INF</span>`);
  }
  chips.push(`<span class="res-chip res-chip-path" title="${escAttr(name)}">${escHtml(shortName(name))}</span>`);
  return chips.join('');
}

function shortName(name) {
  const parts = String(name || '').replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || name || 'file';
}

function renderBody(data) {
  if (data.kind === 'manifest' || data.kind === 'signature') {
    const summary = data.kind === 'signature'
      ? [
          infoRow('Signature-Version', findMainAttr(data.sections, 'Signature-Version')),
          infoRow('Created-By', findMainAttr(data.sections, 'Created-By')),
          infoRow('Manifest digest', data.manifest_digest, { mono: true, title: data.manifest_digest || '' }),
        ].join('')
      : [
          infoRow('Manifest-Version', findMainAttr(data.sections, 'Manifest-Version')),
          infoRow('Created-By', findMainAttr(data.sections, 'Created-By')),
          infoRow('Built-By', findMainAttr(data.sections, 'Built-By')),
        ].join('');
    return `${summary ? `<div class="meta-inf-summary">${summary}</div>` : ''}<div class="meta-inf-filter-wrap"><input type="search" class="meta-inf-filter" placeholder="Filter entries…" aria-label="Filter manifest entries"></div><div class="meta-inf-sections">${renderManifestSections(data.sections || [])}</div>`;
  }
  if (data.kind === 'pkcs7') {
    const certs = Array.isArray(data.certificates) ? data.certificates : [];
    if (!certs.length) {
      return '<div class="muted meta-inf-empty">No X.509 certificates found in this PKCS#7 block. Use the Raw tab for the binary blob.</div>';
    }
    return `<div class="meta-inf-cert-list">${certs.map((c, i) => certBlock(c, i)).join('')}</div>`;
  }
  if (data.raw) {
    return `<pre class="meta-inf-raw info-mono">${escHtml(data.raw)}</pre>`;
  }
  return '<div class="muted meta-inf-empty">Unsupported META-INF file. Use the Raw tab for bytes.</div>';
}

function findMainAttr(sections, key) {
  const main = sections?.[0];
  if (!main?.attributes) return null;
  const hit = main.attributes.find((a) => a.name.toLowerCase() === key.toLowerCase());
  return hit?.value ?? null;
}

/**
 * @param {HTMLElement} container
 * @param {{ name?: string, data: object, bytes?: Uint8Array|ArrayBuffer }} opts
 */
export function mountMetaInfViewer(container, opts) {
  const { name = 'META-INF', data } = opts || {};
  if (!container || !data) return;

  container.innerHTML = `
    <div class="res-viewer meta-inf-viewer">
      <div class="res-viewer-toolbar meta-inf-toolbar">${toolbarChips(data, name)}</div>
      <div class="res-viewer-scroll meta-inf-scroll">${renderBody(data)}</div>
    </div>`;

  const filterInput = container.querySelector('.meta-inf-filter');
  const sectionsHost = container.querySelector('.meta-inf-sections');
  if (filterInput && sectionsHost && (data.kind === 'manifest' || data.kind === 'signature')) {
    filterInput.addEventListener('input', () => {
      sectionsHost.innerHTML = renderManifestSections(data.sections || [], filterInput.value);
    });
  }
}

export function isMetaInfFile(name) {
  const norm = String(name || '').replace(/\\/g, '/');
  const upper = norm.toUpperCase();
  if (!upper.startsWith('META-INF/')) return false;
  const base = upper.split('/').pop() || '';
  return base === 'MANIFEST.MF'
    || base.endsWith('.SF')
    || base.endsWith('.RSA')
    || base.endsWith('.DSA')
    || base.endsWith('.EC');
}

export function metaInfTreeIcon(name) {
  const base = String(name || '').replace(/\\/g, '/').split('/').pop()?.toUpperCase() || '';
  if (base === 'MANIFEST.MF') return ' mf';
  if (base.endsWith('.SF')) return ' sf';
  if (base.endsWith('.RSA') || base.endsWith('.DSA') || base.endsWith('.EC')) return ' sign';
  return ' meta';
}

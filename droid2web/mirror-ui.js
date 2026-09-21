/**
 * Drop-in for droid2web: copy to `web/mirror-ui.js` (scripts/install-droid2web.sh does this).
 *
 * Protocol and coordinate mapping stay in Rust (`MirrorClient`). This file only:
 *   push + app_process launch, open `localabstract:droidmirror`,
 *   readStream → on_bytes → VideoDecoder → canvas, pointer/key → writeStream.
 *
 * webadb is single-flight. The launch shell must return before the mirror stream
 * is opened (`trap "" HUP` + background). Do not call adbShell while the stream is open.
 */
import {
  adbPush,
  adbShell,
  connectAdb,
  isAdbConnected,
  openAbstractStream,
} from './adb-device.js';

const REMOTE_DIR = '/data/local/tmp/droidmirror';
const SOCKET = 'droidmirror';

/** Android keycodes used by `MirrorClient.nav` / `key`. */
export const NAV = {
  home: 3,
  back: 4,
  volUp: 24,
  volDown: 25,
  power: 26,
  recents: 187,
};

const SPECIAL_KEYS = {
  Enter: 66,
  Backspace: 67,
  Tab: 61,
  Escape: 4,
  Delete: 112,
  ArrowUp: 19,
  ArrowDown: 20,
  ArrowLeft: 21,
  ArrowRight: 22,
};

/** @type {import('../pkg/droidmirror_web').MirrorClient | null} */
let client = null;
let running = false;
let wasmReady = null;

export async function loadMirrorClient(wasmFactory) {
  if (!client) {
    const mod = await wasmFactory();
    client = new mod.MirrorClient();
  }
  return client;
}

async function defaultWasmFactory() {
  try {
    const site = await import('./pkg/droid2web.js');
    if (typeof site.MirrorClient === 'function') return site;
  } catch (e) {
    console.warn('droid2web bundle has no MirrorClient yet', e);
  }
  if (!wasmReady) {
    const mirror = await import('./pkg-mirror/droidmirror_web.js');
    wasmReady = mirror.default().then(() => mirror);
  }
  return wasmReady;
}

async function loadAsset(name) {
  const url = new URL(`./mirror/${name}`, import.meta.url);
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error(
      `missing ${name} (${res.status}). From the droidmirror repo run ./scripts/build-server-android.sh`,
    );
  }
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * @param {HTMLCanvasElement} canvas
 * @param {{ so?: Uint8Array, dex?: Uint8Array, bitrate?: number, maxFps?: number, maxSize?: number, wasmFactory?: Function, onStatus?: (s: string) => void }} [opts]
 */
export async function startMirror(canvas, opts = {}) {
  if (!isAdbConnected()) throw new Error('ADB not connected — use Connect phone first');
  if (running) throw new Error('mirror already running');
  if (typeof VideoDecoder === 'undefined') {
    throw new Error('WebCodecs VideoDecoder is missing (use Chrome or Edge)');
  }
  running = true;
  const status = (s) => opts.onStatus?.(s);
  let mirror;
  let ctx;
  let transport = null;
  try {
    mirror = await loadMirrorClient(opts.wasmFactory || defaultWasmFactory);
    ctx = canvas.getContext('2d');
    const bitrate = opts.bitrate ?? 8_000_000;
    const maxFps = opts.maxFps ?? 60;
    const maxSize = opts.maxSize ?? 0;

    status('pushing server…');
    const so = opts.so || await loadAsset('libdroidmirror_server.so');
    const dex = opts.dex || await loadAsset('droidmirror.dex');
    await adbShell(`mkdir -p ${REMOTE_DIR}`);
    await adbPush(so, `${REMOTE_DIR}/libdroidmirror_server.so`);
    await adbPush(dex, `${REMOTE_DIR}/droidmirror.dex`);
    await adbShell(`chmod 755 ${REMOTE_DIR}/libdroidmirror_server.so`);
    await adbShell('pkill -f com.droidmirror.Server || true', 8000);

    const launch =
      `sh -c 'trap "" HUP; CLASSPATH=${REMOTE_DIR}/droidmirror.dex app_process / com.droidmirror.Server` +
      ` --bitrate ${bitrate} --max-fps ${maxFps} --max-size ${maxSize}` +
      ` --lib=${REMOTE_DIR}/libdroidmirror_server.so >/data/local/tmp/droidmirror/server.log 2>&1 &'`;
    status('starting app_process…');
    await adbShell(launch, 20000);

    let lastErr = null;
    for (let i = 0; i < 60; i++) {
      status(`waiting for localabstract:${SOCKET} (${i + 1}/60)…`);
      try {
        transport = await openAbstractStream(SOCKET);
        break;
      } catch (e) {
        lastErr = e;
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    if (!transport) {
      throw lastErr || new Error('localabstract:droidmirror did not open');
    }
  } catch (e) {
    running = false;
    throw e;
  }

  const decoder = new VideoDecoder({
    output(frame) {
      paintFrame(ctx, canvas, frame);
      frame.close();
    },
    error(e) {
      console.error('VideoDecoder', e);
      status(`decoder: ${e?.message || e}`);
    },
  });

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    running = false;
    try { decoder.close(); } catch { /* already closed */ }
    try { await transport.close(); } catch { /* already closed */ }
    try {
      await adbShell('pkill -f com.droidmirror.Server || true', 8000);
    } catch { /* stream may still be draining */ }
    status('stopped');
  };

  wireInput(canvas, mirror, transport);

  let annexBFrames = false;
  (async function readLoop() {
    try {
      status('streaming');
      while (running) {
        const chunk = await transport.read();
        if (!chunk || chunk.length === 0) break;
        if (decoder.decodeQueueSize > 8) mirror.request_keyframe_skip();
        const events = mirror.on_bytes(chunk);
        for (const ev of events) {
          if (ev.kind === 'configure') {
            const packed = packForWebCodecs(ev);
            annexBFrames = packed.annexB;
            decoder.configure(packed.config);
            status(`${ev.width}×${ev.height} ${packed.label}`);
          } else if (ev.kind === 'frame') {
            if (decoder.state !== 'configured') continue;
            decoder.decode(new EncodedVideoChunk({
              type: ev.keyframe ? 'key' : 'delta',
              timestamp: ev.pts,
              data: packFrame(ev.nal, annexBFrames),
            }));
          } else if (ev.kind === 'name') {
            status(ev.name);
          } else if (ev.kind === 'error') {
            console.error('mirror', ev.message);
            status(ev.message);
          }
        }
        await new Promise((r) => setTimeout(r, 0));
      }
    } catch (e) {
      if (running) {
        console.error('mirror read', e);
        status(e?.message || String(e));
      }
    } finally {
      await stop();
    }
  })();

  return { stop, client: mirror, transport };
}

function wireInput(canvas, mirror, transport) {
  let writeChain = Promise.resolve();
  canvas.tabIndex = 0;
  canvas.onpointerdown = (ev) => {
    ev.preventDefault();
    canvas.focus({ preventScroll: true });
    canvas.setPointerCapture?.(ev.pointerId);
    sendTouch(0, ev);
  };
  let pendingMove = null;
  let moveQueued = false;
  canvas.onpointermove = (ev) => {
    if (!ev.buttons) return;
    const rect = canvas.getBoundingClientRect();
    pendingMove = {
      x: ev.clientX - rect.left,
      y: ev.clientY - rect.top,
      w: rect.width,
      h: rect.height,
    };
    if (moveQueued) return;
    moveQueued = true;
    requestAnimationFrame(() => {
      moveQueued = false;
      const sample = pendingMove;
      pendingMove = null;
      if (!sample || !running) return;
      write(mirror.touch(2, 0, sample.x, sample.y, sample.w, sample.h, 1));
    });
  };
  canvas.onpointerup = (ev) => {
    ev.preventDefault();
    sendTouch(1, ev);
  };
  canvas.onpointercancel = (ev) => sendTouch(3, ev);
  canvas.onwheel = (ev) => {
    ev.preventDefault();
    const rect = canvas.getBoundingClientRect();
    write(mirror.scroll(
      ev.clientX - rect.left, ev.clientY - rect.top,
      rect.width, rect.height,
      ev.deltaX / 40, -ev.deltaY / 40,
    ));
  };
  canvas.onkeydown = (ev) => { void onKey(ev, 0); };
  canvas.onkeyup = (ev) => { void onKey(ev, 1); };
  // Keep focus for keyboard when the user clicks nav / stage chrome.
  canvas.addEventListener('click', () => canvas.focus({ preventScroll: true }));

  function sendTouch(action, ev) {
    const rect = canvas.getBoundingClientRect();
    write(mirror.touch(
      action, 0,
      ev.clientX - rect.left, ev.clientY - rect.top,
      rect.width, rect.height, 1,
    ));
  }

  function write(bytes) {
    if (!bytes?.length || !running) return;
    writeChain = writeChain.then(() => transport.write(bytes)).catch((err) => {
      if (!running) return;
      console.error('mirror write', err);
    });
  }

  async function onKey(ev, action) {
    if (!running) return;
    if (ev.key === 'v' && (ev.ctrlKey || ev.metaKey) && action === 0) {
      ev.preventDefault();
      try {
        const text = await navigator.clipboard.readText();
        if (text) write(mirror.text(text));
      } catch (e) {
        console.warn('clipboard', e);
      }
      return;
    }
    if (action === 0 && ev.key.length === 1 && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      ev.preventDefault();
      write(mirror.text(ev.key));
      return;
    }
    const code = SPECIAL_KEYS[ev.key];
    if (code == null) return;
    ev.preventDefault();
    let meta = 0;
    if (ev.shiftKey) meta |= 0x1;
    if (ev.altKey) meta |= 0x2;
    if (ev.ctrlKey || ev.metaKey) meta |= 0x1000;
    write(ev.key === 'Escape' ? mirror.nav(NAV.back, action) : mirror.key(action, code, meta));
  }
}

function paintFrame(ctx, canvas, frame) {
  const vw = canvas.clientWidth || canvas.width;
  const vh = canvas.clientHeight || canvas.height;
  if (canvas.width !== vw || canvas.height !== vh) {
    canvas.width = vw;
    canvas.height = vh;
  }
  ctx.fillStyle = '#000';
  ctx.fillRect(0, 0, vw, vh);
  const aspect = frame.displayWidth / frame.displayHeight;
  const boxAspect = vw / Math.max(vh, 1);
  let dw = vw;
  let dh = vh;
  let dx = 0;
  let dy = 0;
  if (boxAspect > aspect) {
    dh = vh;
    dw = vh * aspect;
    dx = (vw - dw) / 2;
  } else {
    dw = vw;
    dh = vw / aspect;
    dy = (vh - dh) / 2;
  }
  ctx.drawImage(frame, dx, dy, dw, dh);
}

/**
 * WebCodecs wants an AVCDecoderConfigurationRecord plus length-prefixed NALs,
 * not the Annex-B blob the device sends. H.264 only.
 */
function packForWebCodecs(ev) {
  const nals = annexBNals(ev.csd || new Uint8Array());
  const sps = nals.find((n) => (n[0] & 0x1f) === 7);
  const pps = nals.find((n) => (n[0] & 0x1f) === 8);
  if (String(ev.codec).startsWith('hev') || String(ev.codec).startsWith('hvc')) {
    throw new Error('browser decode is H.264 only — leave the codec on h264');
  }
  if (!sps || !pps) {
    return {
      annexB: true,
      label: 'h264 in-band',
      config: { codec: ev.codec || 'avc1.42E01E' },
    };
  }
  const avcC = new Uint8Array(11 + sps.length + pps.length);
  avcC[0] = 1;
  avcC[1] = sps[1];
  avcC[2] = sps[2];
  avcC[3] = sps[3];
  avcC[4] = 0xff;
  avcC[5] = 0xe1;
  avcC[6] = (sps.length >> 8) & 0xff;
  avcC[7] = sps.length & 0xff;
  avcC.set(sps, 8);
  const p = 8 + sps.length;
  avcC[p] = 1;
  avcC[p + 1] = (pps.length >> 8) & 0xff;
  avcC[p + 2] = pps.length & 0xff;
  avcC.set(pps, p + 3);
  const config = { codec: ev.codec || 'avc1.42E01E', description: avcC };
  return { annexB: false, label: `h264 ${ev.codec || ''}`.trim(), config };
}

function packFrame(nal, annexB) {
  if (annexB) return nal;
  const nals = annexBNals(nal);
  if (!nals.length) return nal;
  let size = 0;
  for (const n of nals) size += 4 + n.length;
  const out = new Uint8Array(size);
  let o = 0;
  for (const n of nals) {
    out[o] = (n.length >>> 24) & 0xff;
    out[o + 1] = (n.length >>> 16) & 0xff;
    out[o + 2] = (n.length >>> 8) & 0xff;
    out[o + 3] = n.length & 0xff;
    out.set(n, o + 4);
    o += 4 + n.length;
  }
  return out;
}

function annexBNals(buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf || []);
  if (!u.length) return [];
  const starts = [];
  for (let i = 0; i + 3 < u.length; i++) {
    if (i + 4 < u.length && u[i] === 0 && u[i + 1] === 0 && u[i + 2] === 0 && u[i + 3] === 1) {
      starts.push({ at: i + 4, sc: 4 });
      i += 3;
    } else if (u[i] === 0 && u[i + 1] === 0 && u[i + 2] === 1) {
      starts.push({ at: i + 3, sc: 3 });
      i += 2;
    }
  }
  if (!starts.length) return [u];
  const nals = [];
  for (let i = 0; i < starts.length; i++) {
    const from = starts[i].at;
    const to = i + 1 < starts.length ? starts[i + 1].at - starts[i + 1].sc : u.length;
    if (to > from) nals.push(u.subarray(from, to));
  }
  return nals;
}

/** Wire the Mirror tab. Safe to call if the markup is absent. */
export function initMirrorUi() {
  const startBtn = document.getElementById('mirror-start');
  const canvas = document.getElementById('mirror-canvas');
  if (!startBtn || !canvas) return;

  const stopBtn = document.getElementById('mirror-stop');
  const connectBtn = document.getElementById('mirror-connect');
  const statusEl = document.getElementById('mirror-status');
  const bitrateEl = document.getElementById('mirror-bitrate');
  const maxSizeEl = document.getElementById('mirror-max-size');
  const textEl = document.getElementById('mirror-text');
  const setStatus = (s) => {
    if (statusEl) statusEl.textContent = s;
  };

  let session = null;

  function write(bytes) {
    if (bytes?.length && session?.transport) session.transport.write(bytes);
  }

  connectBtn?.addEventListener('click', async () => {
    connectBtn.disabled = true;
    setStatus('USB picker…');
    try {
      await connectAdb();
      setStatus(isAdbConnected() ? 'phone connected' : 'not connected');
    } catch (e) {
      setStatus(e?.message || String(e));
    } finally {
      connectBtn.disabled = false;
    }
  });

  startBtn.addEventListener('click', async () => {
    startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    try {
      session = await startMirror(canvas, {
        bitrate: Number(bitrateEl?.value || 8_000_000),
        maxFps: 60,
        maxSize: Number(maxSizeEl?.value || 0),
        onStatus: setStatus,
      });
      canvas.focus();
    } catch (e) {
      setStatus(e?.message || String(e));
      startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
    }
  });

  stopBtn?.addEventListener('click', async () => {
    stopBtn.disabled = true;
    const current = session;
    session = null;
    try { await current?.stop(); } catch { /* closed */ }
    startBtn.disabled = false;
  });

  document.querySelectorAll('[data-mirror-nav]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = NAV[btn.getAttribute('data-mirror-nav')];
      if (code == null || !session?.client) return;
      canvas.focus();
      write(session.client.nav(code, 0));
      write(session.client.nav(code, 1));
    });
  });

  textEl?.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter' || !session?.client) return;
    ev.preventDefault();
    const value = textEl.value;
    textEl.value = '';
    if (value) write(session.client.text(value));
  });
}

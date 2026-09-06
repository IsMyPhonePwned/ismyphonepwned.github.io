/**
 * goauld wire protocol (goauld-proto) — length-prefixed frames over a byte stream.
 *
 * Frame: [u32 LE total_len][u8 type][payload…]
 * total_len = 1 + payload.length (includes type byte).
 */

export const MsgType = Object.freeze({
  Hello: 0x01,
  ScriptLoad: 0x02,
  ScriptUnload: 0x03,
  RpcCall: 0x04,
  RpcReply: 0x05,
  Send: 0x06,
  Log: 0x07,
  Post: 0x08,
});

const TYPE_NAME = Object.fromEntries(
  Object.entries(MsgType).map(([k, v]) => [v, k]),
);

const te = new TextEncoder();
const td = new TextDecoder();

export function socketNameForPid(pid) {
  return `goauld-agent-${Number(pid)}`;
}

export function encodeJsonMsg(typeByte, obj) {
  const payload = te.encode(JSON.stringify(obj));
  const total = 1 + payload.length;
  const out = new Uint8Array(4 + total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, total, true);
  out[4] = typeByte;
  out.set(payload, 5);
  return out;
}

export function encodeSendOrPost(typeByte, scriptId, payloadJson, dataBytes = null) {
  const sendPayload = te.encode(
    JSON.stringify({
      script_id: scriptId >>> 0,
      payload_json: typeof payloadJson === 'string' ? payloadJson : JSON.stringify(payloadJson),
    }),
  );
  const data = dataBytes ? (dataBytes instanceof Uint8Array ? dataBytes : new Uint8Array(dataBytes)) : new Uint8Array(0);
  const inner = new Uint8Array(4 + sendPayload.length + 4 + data.length);
  const idv = new DataView(inner.buffer);
  idv.setUint32(0, sendPayload.length, true);
  inner.set(sendPayload, 4);
  idv.setUint32(4 + sendPayload.length, data.length, true);
  if (data.length) inner.set(data, 8 + sendPayload.length);

  const total = 1 + inner.length;
  const out = new Uint8Array(4 + total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, total, true);
  out[4] = typeByte;
  out.set(inner, 5);
  return out;
}

function decodeSendPayload(payload) {
  if (payload.length < 8) return { script_id: 0, payload_json: '', data: null };
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const jsonLen = dv.getUint32(0, true);
  const jsonBytes = payload.subarray(4, 4 + jsonLen);
  let meta = {};
  try {
    meta = JSON.parse(td.decode(jsonBytes));
  } catch {
    meta = { payload_json: td.decode(jsonBytes) };
  }
  const dataOff = 4 + jsonLen;
  const dataLen = dv.getUint32(dataOff, true);
  const data = dataLen > 0 ? payload.subarray(dataOff + 4, dataOff + 4 + dataLen) : null;
  return {
    script_id: meta.script_id ?? 0,
    payload_json: meta.payload_json ?? '',
    data,
  };
}

/**
 * Incremental frame reader over async chunk source.
 * @param {{ read: () => Promise<Uint8Array> }} transport
 */
export class FrameReader {
  constructor(transport) {
    this.transport = transport;
    this.buf = new Uint8Array(0);
  }

  async #fill(minLen) {
    while (this.buf.length < minLen) {
      const chunk = await this.transport.read();
      if (!chunk || !chunk.length) {
        throw new Error('goauld stream closed while reading');
      }
      const next = new Uint8Array(this.buf.length + chunk.length);
      next.set(this.buf);
      next.set(chunk, this.buf.length);
      this.buf = next;
    }
  }

  async readMessage() {
    await this.#fill(4);
    const total = new DataView(this.buf.buffer, this.buf.byteOffset, 4).getUint32(0, true);
    if (total < 1 || total > 16 * 1024 * 1024) {
      throw new Error(`invalid goauld frame length ${total}`);
    }
    await this.#fill(4 + total);
    const frame = this.buf.subarray(4, 4 + total);
    this.buf = this.buf.slice(4 + total);
    const type = frame[0];
    const payload = frame.subarray(1);
    return decodeMessage(type, payload);
  }
}

export function decodeMessage(type, payload) {
  const name = TYPE_NAME[type] || `0x${type.toString(16)}`;
  if (type === MsgType.Send || type === MsgType.Post) {
    const body = decodeSendPayload(payload);
    return { type, name, ...body };
  }
  let json = null;
  if (payload.length) {
    try {
      json = JSON.parse(td.decode(payload));
    } catch {
      json = { _raw: td.decode(payload) };
    }
  }
  return { type, name, json };
}

/**
 * High-level session over an already-opened ADB stream to localabstract:goauld-agent-*.
 *
 * transport: { write(Uint8Array), read()→Uint8Array, close() }
 *
 * IMPORTANT: WebADB's `Adb` methods take `&mut self`. A background read loop plus a
 * concurrent write (ScriptLoad / RpcCall) triggers:
 *   "recursive use of an object detected which would lead to unsafe aliasing in rust"
 * So all I/O is strictly serialized: never read and write overlapping.
 */
export class GoauldSession {
  constructor(transport, { onMessage, onClose } = {}) {
    this.transport = transport;
    this.reader = new FrameReader(transport);
    this.onMessage = onMessage || (() => {});
    this.onClose = onClose || (() => {});
    this.hello = null;
    this.nextCallId = 1;
    this.nextScriptId = 1;
    this._alive = false;
    /** @type {Promise<void>} */
    this._io = Promise.resolve();
  }

  /** Run exclusive I/O on the ADB stream (no overlapping read/write). */
  #exclusive(fn) {
    const run = this._io.then(fn, fn);
    this._io = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  async attach({ expectHello = true } = {}) {
    return this.#exclusive(async () => {
      if (expectHello) {
        const msg = await this.reader.readMessage();
        if (msg.type !== MsgType.Hello) {
          throw new Error(`expected Hello, got ${msg.name}`);
        }
        this.hello = msg.json;
        this.onMessage(msg);
      }
      this._alive = true;
      return this.hello;
    });
  }

  async writeRaw(bytes) {
    return this.#exclusive(() => this.transport.write(bytes));
  }

  async loadScript(source, scriptId = null) {
    const id = scriptId == null ? this.nextScriptId++ : scriptId;
    await this.writeRaw(
      encodeJsonMsg(MsgType.ScriptLoad, { script_id: id, source: String(source) }),
    );
    return id;
  }

  async unloadScript(scriptId) {
    await this.writeRaw(encodeJsonMsg(MsgType.ScriptUnload, { script_id: scriptId >>> 0 }));
  }

  /**
   * Read frames after ScriptLoad. Stops after the first Send/Log by default so we
   * do not block forever waiting for a second frame on a quiet stream.
   */
  async drain({ maxMessages = 8, untilAgentMessage = true } = {}) {
    return this.#exclusive(async () => {
      const out = [];
      if (!this._alive) return out;
      for (let i = 0; i < maxMessages; i++) {
        try {
          const msg = await this.reader.readMessage();
          out.push(msg);
          this.onMessage(msg);
          if (
            untilAgentMessage &&
            (msg.type === MsgType.Send || msg.type === MsgType.Log)
          ) {
            break;
          }
        } catch (e) {
          this._alive = false;
          this.onClose(e);
          throw e;
        }
      }
      return out;
    });
  }

  /**
   * Collect up to maxMessages frames (for live traces). Does not stop on first Send.
   * Blocks until each frame arrives — use while exercising the app.
   */
  async collectMessages({ maxMessages = 40, onFrame = null } = {}) {
    return this.#exclusive(async () => {
      const out = [];
      if (!this._alive) return out;
      for (let i = 0; i < maxMessages; i++) {
        try {
          const msg = await this.reader.readMessage();
          out.push(msg);
          this.onMessage(msg);
          if (typeof onFrame === 'function') onFrame(msg, i + 1, maxMessages);
        } catch (e) {
          this._alive = false;
          this.onClose(e);
          throw e;
        }
      }
      return out;
    });
  }

  /**
   * Write RpcCall, then read until matching RpcReply (Send/Log → onMessage).
   */
  async rpcCall(fnName, args = [], { scriptId = 1, timeoutMs = 30000 } = {}) {
    const callId = this.nextCallId++;
    const argsJson = JSON.stringify(Array.isArray(args) ? args : [args]);
    const frame = encodeJsonMsg(MsgType.RpcCall, {
      script_id: scriptId >>> 0,
      call_id: callId,
      fn_name: String(fnName),
      args_json: argsJson,
    });

    return this.#exclusive(async () => {
      await this.transport.write(frame);
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const msg = await this.reader.readMessage();
        this.onMessage(msg);
        if (msg.type === MsgType.RpcReply && msg.json?.call_id === callId) {
          if (msg.json?.error) throw new Error(msg.json.error);
          return msg.json?.result_json;
        }
      }
      throw new Error(`RPC timeout: ${fnName}`);
    });
  }

  async post(payloadJson, { scriptId = 1, data = null } = {}) {
    await this.writeRaw(encodeSendOrPost(MsgType.Post, scriptId, payloadJson, data));
  }

  async close() {
    this._alive = false;
    return this.#exclusive(async () => {
      try {
        await this.transport.close();
      } catch {
        /* ignore */
      }
    });
  }
}

/** Minimal echo script for smoke-testing attach. */
export const DEFAULT_SMOKE_SCRIPT = `send({type:'ready', from:'droid2web'});
rpc.exports = {
  echo: function (x) { return x; },
  add: function (a, b) { return a + b; },
  ping: function () { return 'pong'; },
};
`;

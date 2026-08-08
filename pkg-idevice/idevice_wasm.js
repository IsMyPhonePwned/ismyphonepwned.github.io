/* @ts-self-types="./idevice_wasm.d.ts" */

//#region exports

/**
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {boolean} verbose
 * @param {string} pair_record_plist_xml
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<string>}
 */
export function lockdownBattery(device, mode, host_id, system_buid, verbose, pair_record_plist_xml, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownBattery(device, ptr0, len0, ptr1, len1, ptr2, len2, verbose, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * `QueryType` → optional `Pair` (generated keys) → `StartSession` → optional TLS → `GetValue battery`.
 * Pass **`pair_record_plist_xml`** to reuse an existing pair record; otherwise keys are generated based on `mode`.
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {boolean} verbose
 * @param {string} pair_record_plist_xml
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<string>}
 */
export function lockdownBatteryPickDevice(mode, host_id, system_buid, verbose, pair_record_plist_xml, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownBatteryPickDevice(ptr0, len0, ptr1, len1, ptr2, len2, verbose, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * `crashreportmover` + AFC crash report copy. Works with either a pre-existing pair-record plist or
 * with generated keys (pair mode `random` / `legacy`) — the latter runs a full `Pair` + Trust flow first.
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @param {boolean} keep
 * @param {string} filter_substr
 * @param {boolean} remove_all
 * @returns {Promise<any>}
 */
export function lockdownCrashReports(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni, keep, filter_substr, remove_all) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    _assertBoolean(keep);
    const ptr6 = passStringToWasm0(filter_substr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    _assertBoolean(remove_all);
    const ret = wasm.lockdownCrashReports(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5, keep, ptr6, len6, remove_all);
    return ret;
}

/**
 * @returns {string}
 */
export function lockdownCrashReportsInfo() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.lockdownCrashReportsInfo();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {boolean} verbose
 * @param {string} pair_record_plist_xml
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<string>}
 */
export function lockdownDiagnostics(device, mode, host_id, system_buid, verbose, pair_record_plist_xml, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownDiagnostics(device, ptr0, len0, ptr1, len1, ptr2, len2, verbose, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * Same as battery, then the diagnostic `GetValue` batch.
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {boolean} verbose
 * @param {string} pair_record_plist_xml
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<string>}
 */
export function lockdownDiagnosticsPickDevice(mode, host_id, system_buid, verbose, pair_record_plist_xml, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownDiagnosticsPickDevice(ptr0, len0, ptr1, len1, ptr2, len2, verbose, ptr3, len3, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * **`QueryType`** → **`StartSession`** → **`GetValue`** batch (cleartext or TLS). Requires a **full** XML pair-record plist
 * (HostID, SystemBUID, and PEM keys). **`tls_client_auth`**: `host` | `root` | `chain`. **`tls_sni`**: `device` | `none`.
 * @param {USBDevice} device
 * @param {string} plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<string>}
 */
export function lockdownFetchWithPlistXml(device, plist_xml, verbose, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr1 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownFetchWithPlistXml(device, ptr0, len0, verbose, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Pair with **freshly generated** RSA keys (random / legacy ids), wait for Trust on the device,
 * and return the resulting pair-record **XML plist** (HostID / SystemBUID / PEM keys) so the page
 * can save it for subsequent `StartSession` + TLS without re-prompting the user.
 * @param {USBDevice} device
 * @param {string} mode
 * @param {boolean} verbose
 * @returns {Promise<string>}
 */
export function lockdownPair(device, mode, verbose) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ret = wasm.lockdownPair(device, ptr0, len0, verbose);
    return ret;
}

/**
 * `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
 * `StartService(com.apple.pcapd)` → secondary mux TCP + TLS → libpcap stream.
 *
 * **Stops** when:
 * - `on_packet` returns `false` → `stoppedReason = "user-stop"`
 * - `packets >= max_packets` (when `max_packets > 0`) → `"max-packets"`
 * - `pcap_bytes >= max_bytes` (when `max_bytes > 0`) → `"max-bytes"`
 * - `max_duration_ms` elapsed → `"max-duration"`
 * - the device closes the relay (cleartext path only) → `"stream-closed"`
 *
 * `data` in the resulting object is a **complete libpcap file** (`LINKTYPE_ETHERNET`, snaplen
 * 65535). The page can blob+download it directly into Wireshark / `tcpdump -r`.
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @param {Function} on_packet
 * @param {string} process_filter
 * @param {string} interface_filter
 * @param {number} max_packets
 * @param {number} max_bytes
 * @param {number} max_duration_ms
 * @returns {Promise<any>}
 */
export function lockdownPcap(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni, on_packet, process_filter, interface_filter, max_packets, max_bytes, max_duration_ms) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(process_filter, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ptr7 = passStringToWasm0(interface_filter, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len7 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownPcap(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5, on_packet, ptr6, len6, ptr7, len7, max_packets, max_bytes, max_duration_ms);
    return ret;
}

/**
 * @param {USBDevice} device
 * @param {boolean} verbose
 * @returns {Promise<string>}
 */
export function lockdownQueryType(device, verbose) {
    _assertBoolean(verbose);
    const ret = wasm.lockdownQueryType(device, verbose);
    return ret;
}

/**
 * `QueryType` on lockdownd (cleartext). **`verbose`**: log mux/TCP details to the browser console.
 * @param {boolean} verbose
 * @returns {Promise<string>}
 */
export function lockdownQueryTypePickDevice(verbose) {
    _assertBoolean(verbose);
    const ret = wasm.lockdownQueryTypePickDevice(verbose);
    return ret;
}

/**
 * `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
 * `StartService(com.apple.mobile.screenshotr)` → secondary TLS → DeviceLink handshake →
 * `ScreenShotRequest` → `ScreenShotReply.ScreenShotData`.
 *
 * Returns `{ data: Uint8Array, extension: "png" | "tiff" | "dat", mime, byteLength }`. The
 * caller decides whether to render it (`<img src="data:image/...">`), download it, or both.
 *
 * **Requires a mounted Developer Disk Image**; otherwise lockdownd answers `InvalidService`
 * and we surface a friendly error.
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<any>}
 */
export function lockdownScreenshot(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownScreenshot(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * Download one sysdiagnose `.tar.gz` by device AFC path (up to ~512 MiB).
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @param {string} device_path
 * @param {Function | null} [on_progress]
 * @returns {Promise<any>}
 */
export function lockdownSysdiagnoseDownload(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni, device_path, on_progress) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(device_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownSysdiagnoseDownload(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5, ptr6, len6, isLikeNone(on_progress) ? 0 : addToExternrefTable0(on_progress));
    return ret;
}

/**
 * @returns {string}
 */
export function lockdownSysdiagnoseInfo() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.lockdownSysdiagnoseInfo();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * List sysdiagnose `.tar.gz` archives on the device (metadata only; no download).
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @returns {Promise<any>}
 */
export function lockdownSysdiagnoseList(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownSysdiagnoseList(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5);
    return ret;
}

/**
 * `QueryType` → optional `Pair` (generated keys) → `StartSession` → TLS upgrade →
 * `StartService(com.apple.syslog_relay)` → secondary mux TCP + (TLS or cleartext) → stream
 * decoded chunks to `on_chunk(text, totalBytes)`.
 *
 * **Stops** when:
 * - `on_chunk` returns `false` → `stoppedReason = "user-stop"`
 * - `accumulated.len() >= max_bytes` (when `max_bytes > 0`) → `"max-bytes"`
 * - `max_duration_ms` elapsed → `"max-duration"`
 * - the device closes the relay (cleartext path only) → `"stream-closed"`
 *
 * Returns `{ bytes, durationMs, stoppedReason, ssl, data: Uint8Array }`. The full byte capture
 * is in `data` so the page can offer **Save** without re-decoding strings.
 * @param {USBDevice} device
 * @param {string} mode
 * @param {string} host_id
 * @param {string} system_buid
 * @param {string} pair_record_plist_xml
 * @param {boolean} verbose
 * @param {string} tls_client_auth
 * @param {string} tls_sni
 * @param {Function} on_chunk
 * @param {number} max_bytes
 * @param {number} max_duration_ms
 * @returns {Promise<any>}
 */
export function lockdownSyslog(device, mode, host_id, system_buid, pair_record_plist_xml, verbose, tls_client_auth, tls_sni, on_chunk, max_bytes, max_duration_ms) {
    const ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(system_buid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(pair_record_plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    _assertBoolean(verbose);
    const ptr4 = passStringToWasm0(tls_client_auth, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(tls_sni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.lockdownSyslog(device, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, verbose, ptr4, len4, ptr5, len5, on_chunk, max_bytes, max_duration_ms);
    return ret;
}

/**
 * After **`requestAppleDevice()`**, run mux + TCP handshake to **lockdownd**.
 * @param {USBDevice} device
 * @param {boolean} verbose
 * @returns {Promise<string>}
 */
export function muxLockdownHandshake(device, verbose) {
    _assertBoolean(verbose);
    const ret = wasm.muxLockdownHandshake(device, verbose);
    return ret;
}

/**
 * Request an Apple USB device (picker) and complete mux **VERSION** (+ **SETUP**) + TCP handshake to **lockdownd**.
 * **`verbose`**: log mux/TCP framing to the browser **`console`** (same spirit as `--lockdown-tls-debug` on the host).
 * @param {boolean} verbose
 * @returns {Promise<string>}
 */
export function muxLockdownHandshakePickDevice(verbose) {
    _assertBoolean(verbose);
    const ret = wasm.muxLockdownHandshakePickDevice(verbose);
    return ret;
}

/**
 * Parse **`HostID`** / **`SystemBUID`** from XML pair-record plist bytes (libimobiledevice-style keys).
 * Returns a JS object `{ hostId, systemBuid }` for use with **`lockdownFetchWithPlistXml`** or manual fields.
 * @param {string} plist_xml
 * @returns {any}
 */
export function pairingIdsFromPlistXml(plist_xml) {
    const ptr0 = passStringToWasm0(plist_xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.pairingIdsFromPlistXml(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Start generating RSA host keys in the background (call right after `requestAppleDevice`).
 * `lockdownPair` consumes the cache so the Trust prompt is not delayed by key generation.
 */
export function prefetchPairHostKeys() {
    wasm.prefetchPairHostKeys();
}

/**
 * `navigator.usb.requestDevice` with Apple **VID 0x05ac** (must run from a user gesture).
 *
 * Fails with a human-friendly diagnostic when `navigator.usb` isn't accessible — the WebUSB
 * API is only exposed in a [secure context](https://developer.mozilla.org/docs/Web/Security/Secure_Contexts)
 * (HTTPS or `localhost`/`127.0.0.1`) on Chromium-based browsers, so users hitting this from
 * `file://` or Firefox/Safari otherwise saw an opaque `Cannot read properties of undefined`
 * crash deep in the wasm-bindgen runtime.
 * @returns {Promise<USBDevice>}
 */
export function requestAppleDevice() {
    const ret = wasm.requestAppleDevice();
    return ret;
}

/**
 * One-time panic hook → `console.error` (helps debug WASM panics in DevTools).
 */
export function wasm_start_hook() {
    wasm.wasm_start_hook();
}

//#endregion

//#region wasm imports
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_boolean_get_6ea149f0a8dcc5ff: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            if (!isLikeNone(ret)) {
                _assertBoolean(ret);
            }
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_ab4b34d23d6778bd: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_3baa9db1a987f47d: function(arg0) {
            const ret = typeof(arg0) === 'function';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_null_52ff4ec04186736f: function(arg0) {
            const ret = arg0 === null;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_object_63322ec0cd6ea4ef: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_string_6df3bf7ef1164ed3: function(arg0) {
            const ret = typeof(arg0) === 'string';
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_is_undefined_29a43b4d42920abd: function(arg0) {
            const ret = arg0 === undefined;
            _assertBoolean(ret);
            return ret;
        },
        __wbg___wbindgen_string_get_7ed5322991caaec5: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6b64449b9b9ed33c: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_b46c9b5a9f08ec37: function() { return logError(function (arg0) {
            arg0._wbg_cb_unref();
        }, arguments); },
        __wbg_alternateSetting_8a8bcceaf24310f2: function() { return logError(function (arg0) {
            const ret = arg0.alternateSetting;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_alternates_3ccfb6401b397322: function() { return logError(function (arg0) {
            const ret = arg0.alternates;
            return ret;
        }, arguments); },
        __wbg_buffer_fe2a4eb55dabaee4: function() { return logError(function (arg0) {
            const ret = arg0.buffer;
            return ret;
        }, arguments); },
        __wbg_byteLength_00a2eac5f400a27f: function() { return logError(function (arg0) {
            const ret = arg0.byteLength;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_byteOffset_00f4a4cea0138447: function() { return logError(function (arg0) {
            const ret = arg0.byteOffset;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_call_a24592a6f349a97e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_call_bb28efe6b2f55b86: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.call(arg1, arg2, arg3);
            return ret;
        }, arguments); },
        __wbg_claimInterface_a8f031bf3abc8e57: function() { return logError(function (arg0, arg1) {
            const ret = arg0.claimInterface(arg1);
            return ret;
        }, arguments); },
        __wbg_clearHalt_ac1536dfbd2fca94: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.clearHalt(__wbindgen_enum_UsbDirection[arg1], arg2);
            return ret;
        }, arguments); },
        __wbg_clearTimeout_113b1cde814ec762: function() { return logError(function (arg0) {
            const ret = clearTimeout(arg0);
            return ret;
        }, arguments); },
        __wbg_configurationValue_bd7ff91f56bf6581: function() { return logError(function (arg0) {
            const ret = arg0.configurationValue;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_configuration_f6c3506f079683f8: function() { return logError(function (arg0) {
            const ret = arg0.configuration;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_configurations_e68ac74c72d29f53: function() { return logError(function (arg0) {
            const ret = arg0.configurations;
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function() { return logError(function (arg0) {
            const ret = arg0.crypto;
            return ret;
        }, arguments); },
        __wbg_data_2af3a1b5d549933a: function() { return logError(function (arg0) {
            const ret = arg0.data;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_debug_c014a160490283dc: function() { return logError(function (arg0) {
            console.debug(arg0);
        }, arguments); },
        __wbg_direction_2d7129d77e2b531d: function() { return logError(function (arg0) {
            const ret = arg0.direction;
            return (__wbindgen_enum_UsbDirection.indexOf(ret) + 1 || 3) - 1;
        }, arguments); },
        __wbg_endpointNumber_4e7d6181cd8b08ec: function() { return logError(function (arg0) {
            const ret = arg0.endpointNumber;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_endpoints_d797ff38581325fe: function() { return logError(function (arg0) {
            const ret = arg0.endpoints;
            return ret;
        }, arguments); },
        __wbg_error_a6fa202b58aa1cd3: function() { return logError(function (arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getTime_da7c55f52b71e8c6: function() { return logError(function (arg0) {
            const ret = arg0.getTime();
            return ret;
        }, arguments); },
        __wbg_get_6011fa3a58f61074: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_8360291721e2339f: function() { return logError(function (arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbAlternateInterface_2d171503b4a168b7: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBAlternateInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbConfiguration_dd410ac80164ac9f: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBConfiguration;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbDevice_6064d86d736928da: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBDevice;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbEndpoint_af653a0968646d70: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBEndpoint;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbInTransferResult_b97be62830953127: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBInTransferResult;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_UsbInterface_519993e82bf11037: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_instanceof_Window_cc64c86c8ef9e02b: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_interfaceClass_f68a334eedd369ad: function() { return logError(function (arg0) {
            const ret = arg0.interfaceClass;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_interfaceNumber_3007adf31d099bb6: function() { return logError(function (arg0) {
            const ret = arg0.interfaceNumber;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_interfaceSubclass_2268b119516b12a6: function() { return logError(function (arg0) {
            const ret = arg0.interfaceSubclass;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_interfaces_121a3ce782f7425d: function() { return logError(function (arg0) {
            const ret = arg0.interfaces;
            return ret;
        }, arguments); },
        __wbg_length_3d4ecd04bd8d22f1: function() { return logError(function (arg0) {
            const ret = arg0.length;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_length_9f1775224cf1d815: function() { return logError(function (arg0) {
            const ret = arg0.length;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_log_7e1aa9064a1dbdbd: function() { return logError(function (arg0) {
            console.log(arg0);
        }, arguments); },
        __wbg_msCrypto_bd5a034af96bcba6: function() { return logError(function (arg0) {
            const ret = arg0.msCrypto;
            return ret;
        }, arguments); },
        __wbg_navigator_bc077756492232c5: function() { return logError(function (arg0) {
            const ret = arg0.navigator;
            return ret;
        }, arguments); },
        __wbg_new_0_4d657201ced14de3: function() { return logError(function () {
            const ret = new Date();
            return ret;
        }, arguments); },
        __wbg_new_227d7c05414eb861: function() { return logError(function () {
            const ret = new Error();
            return ret;
        }, arguments); },
        __wbg_new_682678e2f47e32bc: function() { return logError(function () {
            const ret = new Array();
            return ret;
        }, arguments); },
        __wbg_new_aa8d0fa9762c29bd: function() { return logError(function () {
            const ret = new Object();
            return ret;
        }, arguments); },
        __wbg_new_typed_323f37fd55ab048d: function() { return logError(function (arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h79c2b90df5b83fd6(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        }, arguments); },
        __wbg_new_with_byte_offset_and_length_01848e8d6a3d49ad: function() { return logError(function (arg0, arg1, arg2) {
            const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_new_with_length_8c854e41ea4dae9b: function() { return logError(function (arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function() { return logError(function (arg0) {
            const ret = arg0.node;
            return ret;
        }, arguments); },
        __wbg_now_a9b7df1cbee90986: function() { return logError(function () {
            const ret = Date.now();
            return ret;
        }, arguments); },
        __wbg_open_dda0e3fbb5fdf717: function() { return logError(function (arg0) {
            const ret = arg0.open();
            return ret;
        }, arguments); },
        __wbg_opened_9381037b274115fa: function() { return logError(function (arg0) {
            const ret = arg0.opened;
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function() { return logError(function (arg0) {
            const ret = arg0.process;
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_a6b02eb00b0f4ce2: function() { return logError(function (arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        }, arguments); },
        __wbg_push_471a5b068a5295f6: function() { return logError(function (arg0, arg1) {
            const ret = arg0.push(arg1);
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_queueMicrotask_5d15a957e6aa920e: function() { return logError(function (arg0) {
            queueMicrotask(arg0);
        }, arguments); },
        __wbg_queueMicrotask_f8819e5ffc402f36: function() { return logError(function (arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        }, arguments); },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_releaseInterface_efc346aed0b92650: function() { return logError(function (arg0, arg1) {
            const ret = arg0.releaseInterface(arg1);
            return ret;
        }, arguments); },
        __wbg_requestDevice_f6f19fa3d4de58f3: function() { return logError(function (arg0, arg1) {
            const ret = arg0.requestDevice(arg1);
            return ret;
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_reset_71b7f9ff93aea3a0: function() { return logError(function (arg0) {
            const ret = arg0.reset();
            return ret;
        }, arguments); },
        __wbg_resolve_e6c466bc1052f16c: function() { return logError(function (arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        }, arguments); },
        __wbg_run_0b0a622deae25fda: function() { return logError(function (arg0, arg1, arg2) {
            try {
                var state0 = {a: arg1, b: arg2};
                var cb0 = () => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__ha9d65b68881a71f8(a, state0.b, );
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = arg0.run(cb0);
                _assertBoolean(ret);
                return ret;
            } finally {
                state0.a = 0;
            }
        }, arguments); },
        __wbg_selectAlternateInterface_dd9681da0d48cb08: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.selectAlternateInterface(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_selectConfiguration_23c3fda516d9db6b: function() { return logError(function (arg0, arg1) {
            const ret = arg0.selectConfiguration(arg1);
            return ret;
        }, arguments); },
        __wbg_setTimeout_ef24d2fc3ad97385: function() { return handleError(function (arg0, arg1) {
            const ret = setTimeout(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_set_022bee52d0b05b19: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            _assertBoolean(ret);
            return ret;
        }, arguments); },
        __wbg_set_3d484eb794afec82: function() { return logError(function (arg0, arg1, arg2) {
            arg0.set(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_set_filters_e3b6bb2c5e815273: function() { return logError(function (arg0, arg1, arg2) {
            arg0.filters = getArrayJsValueViewFromWasm0(arg1, arg2);
        }, arguments); },
        __wbg_set_vendor_id_871b993d1cd4e9b1: function() { return logError(function (arg0, arg1) {
            arg0.vendorId = arg1;
        }, arguments); },
        __wbg_stack_3b0d974bbf31e44f: function() { return logError(function (arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_static_accessor_CREATE_TASK_f3ab6a6954bda493: function() { return logError(function () {
            const ret = typeof console === 'undefined' ? null : console?.createTask;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_8cfadc87a297ca02: function() { return logError(function () {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_602256ae5c8f42cf: function() { return logError(function () {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_SELF_e445c1c7484aecc3: function() { return logError(function () {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_static_accessor_WINDOW_f20e8576ef1e0f17: function() { return logError(function () {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_subarray_f8ca46a25b1f5e0d: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_then_792e0c862b060889: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_then_8e16ee11f05e4827: function() { return logError(function (arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        }, arguments); },
        __wbg_transferIn_73312959902627aa: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.transferIn(arg1, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_transferOut_18df839572808dcb: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.transferOut(arg1, getArrayU8FromWasm0(arg2, arg3));
            return ret;
        }, arguments); },
        __wbg_type_10ba6a9890e8273d: function() { return logError(function (arg0) {
            const ret = arg0.type;
            return (__wbindgen_enum_UsbEndpointType.indexOf(ret) + 1 || 4) - 1;
        }, arguments); },
        __wbg_usb_d215c066f98aed0e: function() { return logError(function (arg0) {
            const ret = arg0.usb;
            return ret;
        }, arguments); },
        __wbg_versions_276b2795b1c6a219: function() { return logError(function (arg0) {
            const ret = arg0.versions;
            return ret;
        }, arguments); },
        __wbg_warn_3cc416af27dbdc02: function() { return logError(function (arg0) {
            console.warn(arg0);
        }, arguments); },
        __wbindgen_cast_0000000000000001: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 1005, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h3b1bed7b91f8cd80);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000002: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBDevice")], shim_idx: 83, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hc357b3aa832c9207);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000003: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBInTransferResult")], shim_idx: 81, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h5ac59dc61f1429fb);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000004: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBOutTransferResult")], shim_idx: 82, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h794745f3c166606a);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000005: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("undefined")], shim_idx: 84, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h0b8e8432df29340a);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000006: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [], shim_idx: 976, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hbb78a02d74e2e8bc);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000007: function() { return logError(function (arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000008: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000009: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./idevice_wasm_bg.js": import0,
    };
}


//#endregion
function wasm_bindgen__convert__closures_____invoke__hbb78a02d74e2e8bc(arg0, arg1) {
    _assertNum(arg0);
    _assertNum(arg1);
    wasm.wasm_bindgen__convert__closures_____invoke__hbb78a02d74e2e8bc(arg0, arg1);
}

function wasm_bindgen__convert__closures_____invoke__ha9d65b68881a71f8(arg0, arg1) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__ha9d65b68881a71f8(arg0, arg1);
    return ret !== 0;
}

function wasm_bindgen__convert__closures_____invoke__h3b1bed7b91f8cd80(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h3b1bed7b91f8cd80(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__hc357b3aa832c9207(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hc357b3aa832c9207(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h5ac59dc61f1429fb(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h5ac59dc61f1429fb(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h794745f3c166606a(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h794745f3c166606a(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h0b8e8432df29340a(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h0b8e8432df29340a(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h79c2b90df5b83fd6(arg0, arg1, arg2, arg3) {
    _assertNum(arg0);
    _assertNum(arg1);
    wasm.wasm_bindgen__convert__closures_____invoke__h79c2b90df5b83fd6(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_UsbDirection = ["in", "out"];


const __wbindgen_enum_UsbEndpointType = ["bulk", "interrupt", "isochronous"];


//#region intrinsics
function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertBoolean(n) {
    if (typeof(n) !== 'boolean') {
        throw new Error(`expected a boolean argument, found ${typeof(n)}`);
    }
}

function _assertNum(n) {
    if (typeof(n) !== 'number') throw new Error(`expected a number argument, found ${typeof(n)}`);
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueViewFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function logError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        let error = (function () {
            try {
                return e instanceof Error ? `${e.message}\n\nStack:\n${e.stack}` : e.toString();
            } catch(_) {
                return "<failed to stringify thrown value>";
            }
        }());
        console.error("wasm-bindgen: imported JS function that was not marked as `catch` threw an error:", error);
        throw e;
    }
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (typeof(arg) !== 'string') throw new Error(`expected a string argument, found ${typeof(arg)}`);
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);
        if (ret.read !== arg.length) throw new Error('failed to pass whole string');
        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;


//#endregion

//#region wasm loading
let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('idevice_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
//#endregion
export { wasm as __wasm }

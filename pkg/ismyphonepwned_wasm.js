/* @ts-self-types="./ismyphonepwned_wasm.d.ts" */

//#region exports

/**
 * Main ADB interface for JavaScript
 */
export class Adb {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AdbFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_adb_free(ptr, 0);
    }
    /**
     * Get active stream count
     * @returns {number}
     */
    active_stream_count() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_active_stream_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {Uint8Array} data
     * @param {string} rules
     * @returns {Promise<any>}
     */
    analyze_bugreport(data, rules) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(rules, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adb_analyze_bugreport(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Analyze a bugreport downloaded from device path
     * Downloads the bugreport and analyzes it in one step.
     * `rules` is YAML string of Sigma rules (can be concatenated with "\n---\n" as document separator).
     * @param {string} path
     * @param {string} rules
     * @returns {Promise<any>}
     */
    analyze_bugreport_from_device(path, rules) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(rules, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adb_analyze_bugreport_from_device(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Analyze a bugreport and get detailed security analysis
     * Returns detailed security findings as JSON
     * @param {Uint8Array} data
     * @returns {Promise<any>}
     */
    analyze_bugreport_security(data) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_analyze_bugreport_security(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Generate a full bugreport (can take several minutes)
     * Returns the bugreport as a Uint8Array
     * @returns {Promise<Uint8Array>}
     */
    bugreport() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_bugreport(this.__wbg_ptr);
        return ret;
    }
    /**
     * Generate a lightweight bugreport (much faster)
     * Returns a text summary
     * @returns {Promise<string>}
     */
    bugreport_lite() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_bugreport_lite(this.__wbg_ptr);
        return ret;
    }
    /**
     * Cleanup stale streams (>30 seconds old)
     * @returns {Promise<number>}
     */
    cleanup_stale_streams() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_cleanup_stale_streams(this.__wbg_ptr);
        return ret;
    }
    /**
     * Request device and connect
     * Returns device information as JSON
     * @returns {Promise<any>}
     */
    connect() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_connect(this.__wbg_ptr);
        return ret;
    }
    /**
     * Connect using a `USBDevice` from `navigator.usb.requestDevice()` in JavaScript.
     *
     * Chrome expects `requestDevice` to run from a **user gesture**. If the first `await` in
     * your click handler is `adb.connect()`, WASM may run `requestDevice` on a later turn and
     * the picker / phone authorization flow can fail. Call `requestDevice` in JS first, then pass
     * the device here.
     * @param {any} usb_device
     * @returns {Promise<any>}
     */
    connectWithUsbDevice(usb_device) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_connectWithUsbDevice(this.__wbg_ptr, usb_device);
        return ret;
    }
    /**
     * Create a directory (with parent directories)
     * @param {string} remote_path
     * @returns {Promise<void>}
     */
    create_directory(remote_path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(remote_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_create_directory(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Delete a file or directory
     * @param {string} remote_path
     * @returns {Promise<void>}
     */
    delete_path(remote_path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(remote_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_delete_path(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Disconnect from device
     * @returns {Promise<void>}
     */
    disconnect() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_disconnect(this.__wbg_ptr);
        return ret;
    }
    /**
     * Download a specific bugreport by path
     * Returns the file data as a Uint8Array
     * @param {string} path
     * @returns {Promise<Uint8Array>}
     */
    download_bugreport(path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_download_bugreport(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Get full bugreport data as JSON for inspection
     * @param {Uint8Array} data
     * @returns {Promise<any>}
     */
    get_bugreport_full_data(data) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_get_bugreport_full_data(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Get device properties
     * @returns {Promise<any>}
     */
    get_properties() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_get_properties(this.__wbg_ptr);
        return ret;
    }
    /**
     * Check device health
     * @returns {Promise<boolean>}
     */
    health_check() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_health_check(this.__wbg_ptr);
        return ret;
    }
    /**
     * Check if connected
     * @returns {boolean}
     */
    is_connected() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_is_connected(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * List available bugreports on device
     * Returns array of file paths
     * @returns {Promise<any>}
     */
    list_bugreports() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_list_bugreports(this.__wbg_ptr);
        return ret;
    }
    /**
     * List directory contents
     * @param {string} path
     * @returns {Promise<any>}
     */
    list_directory(path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_list_directory(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Get logcat output (last n lines)
     * @param {number} lines
     * @returns {Promise<string>}
     */
    logcat(lines) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        _assertNum(lines);
        const ret = wasm.adb_logcat(this.__wbg_ptr, lines);
        return ret;
    }
    /**
     * Clear logcat buffer
     * @returns {Promise<void>}
     */
    logcat_clear() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.adb_logcat_clear(this.__wbg_ptr);
        return ret;
    }
    /**
     * Create a new ADB instance
     */
    constructor() {
        const ret = wasm.adb_new();
        this.__wbg_ptr = ret >>> 0;
        AdbFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Pull a file from the device
     * Returns the file data as a Uint8Array
     * @param {string} path
     * @returns {Promise<Uint8Array>}
     */
    pull_file(path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_pull_file(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Push (upload) a file to device
     * @param {Uint8Array} data
     * @param {string} remote_path
     * @returns {Promise<void>}
     */
    push_file(data, remote_path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adb_push_file(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Reboot the device
     * target can be "bootloader", "recovery", or null for normal reboot
     * @param {string | null} [target]
     * @returns {Promise<void>}
     */
    reboot(target) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        var ptr0 = isLikeNone(target) ? 0 : passStringToWasm0(target, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_reboot(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Rename or move a file/directory
     * @param {string} old_path
     * @param {string} new_path
     * @returns {Promise<void>}
     */
    rename_file(old_path, new_path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(old_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(new_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adb_rename_file(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Execute a shell command
     * @param {string} command
     * @returns {Promise<string>}
     */
    shell(command) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_shell(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Execute shell command with timeout
     * @param {string} command
     * @param {number} timeout_ms
     * @returns {Promise<string>}
     */
    shell_with_timeout(command, timeout_ms) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        _assertNum(timeout_ms);
        const ret = wasm.adb_shell_with_timeout(this.__wbg_ptr, ptr0, len0, timeout_ms);
        return ret;
    }
    /**
     * Get file statistics
     * @param {string} path
     * @returns {Promise<any>}
     */
    stat_file(path) {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_stat_file(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) Adb.prototype[Symbol.dispose] = Adb.prototype.free;

export class JsDeviceInfo {
    constructor() {
        throw new Error('cannot invoke `new` directly');
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        JsDeviceInfoFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_jsdeviceinfo_free(ptr, 0);
    }
    /**
     * @returns {string | undefined}
     */
    get manufacturer() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.jsdeviceinfo_manufacturer(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {string | undefined}
     */
    get product() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.jsdeviceinfo_product(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {number}
     */
    get product_id() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.jsdeviceinfo_product_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string | undefined}
     */
    get serial() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.jsdeviceinfo_serial(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {number}
     */
    get vendor_id() {
        if (this.__wbg_ptr == 0) throw new Error('Attempt to use a moved value');
        _assertNum(this.__wbg_ptr);
        const ret = wasm.jsdeviceinfo_vendor_id(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) JsDeviceInfo.prototype[Symbol.dispose] = JsDeviceInfo.prototype.free;

/**
 * Analyze Android **Intrusion Logging** (AAPM) NDJSON from uploaded file bytes.
 *
 * `payload` is JSON: `{ "files": [ { "name": "intrusion.txt", "data": [u8, ...] } ] }`.
 * Each file may be a `.txt` log or `.zip` (AndroidQF-style layout). Returns a JSON string for
 * `JSON.parse` in JS — same pattern as [`analyze_sysdiagnose`].
 *
 * Shape: `{ ok, parser, meta, stats, parsers, analysers: { timesketch } }`.
 * @param {string} payload
 * @returns {any}
 */
export function analyzeIntrusionLogs(payload) {
    const ptr0 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.analyzeIntrusionLogs(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Analyze an Apple **sysdiagnose** `.tar.gz` from bytes using
 * [sysdiagnose-extractor-library](https://github.com/IsMyPhonePwned/sysdiagnose-extractor-library).
 *
 * Returns a **JSON string** (parse with `JSON.parse` in JS). Nested `serde_json::Value` does not
 * round-trip through `serde_wasm_bindgen::to_value` as plain objects; string encoding avoids
 * empty `Map`/opaque objects in the browser.
 *
 * Shape: `{ ok, parser, meta, stats, parsers, analysers }` where `parsers` maps each SAF module
 * name to `{ ok, duration_ms, data? | error? }`, and `analysers` maps SAF analyser ids (same as
 * `sdx-cli --run-analysers`) to summary JSON or `{ "error": ... }`.
 * @param {Uint8Array} tar_gz
 * @returns {any}
 */
export function analyzeSysdiagnose(tar_gz) {
    const ptr0 = passArray8ToWasm0(tar_gz, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.analyzeSysdiagnose(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {Uint8Array} zip_data
 * @returns {Uint8Array}
 */
export function extract_dumpstate_wasm(zip_data) {
    const ptr0 = passArray8ToWasm0(zip_data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.extract_dumpstate_wasm(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Generate a new RSA keypair and save it
 */
export function generate_keypair() {
    const ret = wasm.generate_keypair();
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Check if a keypair is stored
 * @returns {boolean}
 */
export function has_keypair() {
    const ret = wasm.has_keypair();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Initialize the WASM module
 */
export function init() {
    wasm.init();
}

/**
 * @param {Uint8Array} data
 * @returns {boolean}
 */
export function is_zip_file_wasm(data) {
    const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.is_zip_file_wasm(ptr0, len0);
    return ret !== 0;
}

/**
 * Remove stored keypair
 */
export function remove_keypair() {
    const ret = wasm.remove_keypair();
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

//#endregion

//#region wasm imports
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_960c155d3d49e4c2: function() { return logError(function (arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_String_8564e559799eccda: function() { return logError(function (arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
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
        __wbg___wbindgen_throw_6b64449b9b9ed33c: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_b46c9b5a9f08ec37: function() { return logError(function (arg0) {
            arg0._wbg_cb_unref();
        }, arguments); },
        __wbg_alternates_3ccfb6401b397322: function() { return logError(function (arg0) {
            const ret = arg0.alternates;
            return ret;
        }, arguments); },
        __wbg_buffer_fe2a4eb55dabaee4: function() { return logError(function (arg0) {
            const ret = arg0.buffer;
            return ret;
        }, arguments); },
        __wbg_call_a24592a6f349a97e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_claimInterface_a8f031bf3abc8e57: function() { return logError(function (arg0, arg1) {
            const ret = arg0.claimInterface(arg1);
            return ret;
        }, arguments); },
        __wbg_close_2a1a54563b3e4828: function() { return logError(function (arg0) {
            const ret = arg0.close();
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
        __wbg_error_2001591ad2463697: function() { return logError(function (arg0) {
            console.error(arg0);
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
        __wbg_getItem_7fe1351b9ea3b2f3: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getItem(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getTime_da7c55f52b71e8c6: function() { return logError(function (arg0) {
            const ret = arg0.getTime();
            return ret;
        }, arguments); },
        __wbg_get_8360291721e2339f: function() { return logError(function (arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        }, arguments); },
        __wbg_info_7479429238bffbce: function() { return logError(function (arg0) {
            console.info(arg0);
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
        __wbg_instanceof_UsbOutTransferResult_1600f68bf1c72b8b: function() { return logError(function (arg0) {
            let result;
            try {
                result = arg0 instanceof USBOutTransferResult;
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
        __wbg_interfaceProtocol_959cb11cb1f1bc38: function() { return logError(function (arg0) {
            const ret = arg0.interfaceProtocol;
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
        __wbg_localStorage_f5f66b1ffd2486bc: function() { return handleError(function (arg0) {
            const ret = arg0.localStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_log_7e1aa9064a1dbdbd: function() { return logError(function (arg0) {
            console.log(arg0);
        }, arguments); },
        __wbg_manufacturerName_97333dcc3ff0d0e4: function() { return logError(function (arg0, arg1) {
            const ret = arg1.manufacturerName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
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
        __wbg_new_0c7403db6e782f19: function() { return logError(function (arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        }, arguments); },
        __wbg_new_227d7c05414eb861: function() { return logError(function () {
            const ret = new Error();
            return ret;
        }, arguments); },
        __wbg_new_34d45cc8e36aaead: function() { return logError(function () {
            const ret = new Map();
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
        __wbg_new_from_slice_b5ea43e23f6008c0: function() { return logError(function (arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_new_typed_323f37fd55ab048d: function() { return logError(function (arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h8d00bc049a52a329(a, state0.b, arg0, arg1);
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
        __wbg_new_with_length_8c854e41ea4dae9b: function() { return logError(function (arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function() { return logError(function (arg0) {
            const ret = arg0.node;
            return ret;
        }, arguments); },
        __wbg_now_36a3148ac47c4ad7: function() { return logError(function (arg0) {
            const ret = arg0.now();
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
        __wbg_performance_e0409977f06d6f6b: function() { return logError(function (arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function() { return logError(function (arg0) {
            const ret = arg0.process;
            return ret;
        }, arguments); },
        __wbg_productId_dc5889477b3f310d: function() { return logError(function (arg0) {
            const ret = arg0.productId;
            _assertNum(ret);
            return ret;
        }, arguments); },
        __wbg_productName_4daa9f48f42b5ea1: function() { return logError(function (arg0, arg1) {
            const ret = arg1.productName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_prototypesetcall_a6b02eb00b0f4ce2: function() { return logError(function (arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
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
        __wbg_removeItem_487c385a3066a8ed: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_requestDevice_f6f19fa3d4de58f3: function() { return logError(function (arg0, arg1) {
            const ret = arg0.requestDevice(arg1);
            return ret;
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
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
                        return wasm_bindgen__convert__closures_____invoke__h0d7732cbb2d8cf7d(a, state0.b, );
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
        __wbg_selectConfiguration_23c3fda516d9db6b: function() { return logError(function (arg0, arg1) {
            const ret = arg0.selectConfiguration(arg1);
            return ret;
        }, arguments); },
        __wbg_serialNumber_922a86fad8359b45: function() { return logError(function (arg0, arg1) {
            const ret = arg1.serialNumber;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_setItem_e6399d3faae141dc: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_3bf1de9fab0cd644: function() { return logError(function (arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        }, arguments); },
        __wbg_set_6be42768c690e380: function() { return logError(function (arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        }, arguments); },
        __wbg_set_class_code_f2c86de0aeec4677: function() { return logError(function (arg0, arg1) {
            arg0.classCode = arg1;
        }, arguments); },
        __wbg_set_fde2cec06c23692b: function() { return logError(function (arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_filters_e3b6bb2c5e815273: function() { return logError(function (arg0, arg1, arg2) {
            arg0.filters = getArrayJsValueViewFromWasm0(arg1, arg2);
        }, arguments); },
        __wbg_set_protocol_code_8e93f47a42815568: function() { return logError(function (arg0, arg1) {
            arg0.protocolCode = arg1;
        }, arguments); },
        __wbg_set_subclass_code_96bcffb7cdd6df9e: function() { return logError(function (arg0, arg1) {
            arg0.subclassCode = arg1;
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
        __wbg_status_4a602cc40a398032: function() { return logError(function (arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
        }, arguments); },
        __wbg_status_ed090fdfb46aaa13: function() { return logError(function (arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
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
        __wbg_transferOut_6ec6d24b87389c1d: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transferOut(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_usb_d215c066f98aed0e: function() { return logError(function (arg0) {
            const ret = arg0.usb;
            return ret;
        }, arguments); },
        __wbg_vendorId_3f358e252215e9d5: function() { return logError(function (arg0) {
            const ret = arg0.vendorId;
            _assertNum(ret);
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
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 1700, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__h3282b50727b2654b);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000002: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBDevice")], shim_idx: 603, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__ha8c9480eaf831430);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000003: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBInTransferResult")], shim_idx: 601, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hd61ba2f23b84e1e7);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000004: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBOutTransferResult")], shim_idx: 600, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__he6538411cf268f5c);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000005: function() { return logError(function (arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("undefined")], shim_idx: 602, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hfebd3b5d46931d97);
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000006: function() { return logError(function (arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        }, arguments); },
        __wbindgen_cast_0000000000000007: function() { return logError(function (arg0) {
            // Cast intrinsic for `I64 -> Externref`.
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
        __wbindgen_cast_000000000000000a: function() { return logError(function (arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
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
        "./ismyphonepwned_wasm_bg.js": import0,
    };
}


//#endregion
function wasm_bindgen__convert__closures_____invoke__h0d7732cbb2d8cf7d(arg0, arg1) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h0d7732cbb2d8cf7d(arg0, arg1);
    return ret !== 0;
}

function wasm_bindgen__convert__closures_____invoke__h3282b50727b2654b(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h3282b50727b2654b(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__ha8c9480eaf831430(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__ha8c9480eaf831430(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__hd61ba2f23b84e1e7(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hd61ba2f23b84e1e7(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__he6538411cf268f5c(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__he6538411cf268f5c(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__hfebd3b5d46931d97(arg0, arg1, arg2) {
    _assertNum(arg0);
    _assertNum(arg1);
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hfebd3b5d46931d97(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h8d00bc049a52a329(arg0, arg1, arg2, arg3) {
    _assertNum(arg0);
    _assertNum(arg1);
    wasm.wasm_bindgen__convert__closures_____invoke__h8d00bc049a52a329(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_UsbDirection = ["in", "out"];


const __wbindgen_enum_UsbTransferStatus = ["ok", "stall", "babble"];
const AdbFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_adb_free(ptr >>> 0, 1));
const JsDeviceInfoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_jsdeviceinfo_free(ptr >>> 0, 1));


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

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
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
        module_or_path = new URL('ismyphonepwned_wasm_bg.wasm', import.meta.url);
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

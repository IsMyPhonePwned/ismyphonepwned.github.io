/* @ts-self-types="./webadb_rs.d.ts" */

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
        const ret = wasm.adb_active_stream_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Run on-device `backup:` and stream an Android Backup (`.ab`) archive.
     *
     * `args` is the flag/package list after `backup:` (same as platform `adb backup` without `-f`),
     * e.g. `"-nocompress com.android.providers.telephony"` or `"-nocompress -apk -all"`.
     * Confirm the backup UI on the phone. Can take a long time; result is buffered in memory.
     *
     * For large / full-device backups prefer [`Self::backup_stream`], which writes chunks via a
     * JS callback (e.g. File System Access API) without holding the whole archive in WASM.
     * @param {string} args
     * @returns {Promise<Uint8Array>}
     */
    backup(args) {
        const ptr0 = passStringToWasm0(args, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_backup(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Stream `backup:` chunks to a JS callback instead of buffering the whole `.ab` in WASM.
     *
     * `on_chunk` is called with each `Uint8Array` payload. It may return a `Promise` (awaited)
     * — use that to `writable.write(chunk)` via the File System Access API.
     *
     * Returns total bytes streamed. Confirm the backup UI on the phone.
     * @param {string} args
     * @param {Function} on_chunk
     * @returns {Promise<number>}
     */
    backupStream(args, on_chunk) {
        const ptr0 = passStringToWasm0(args, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_backupStream(this.__wbg_ptr, ptr0, len0, on_chunk);
        return ret;
    }
    /**
     * Generate a full bugreport (can take several minutes)
     * Returns the bugreport as a Uint8Array
     * @returns {Promise<Uint8Array>}
     */
    bugreport() {
        const ret = wasm.adb_bugreport(this.__wbg_ptr);
        return ret;
    }
    /**
     * Generate a lightweight bugreport (much faster)
     * Returns a text summary
     * @returns {Promise<string>}
     */
    bugreport_lite() {
        const ret = wasm.adb_bugreport_lite(this.__wbg_ptr);
        return ret;
    }
    /**
     * Cleanup stale streams (>30 seconds old)
     * @returns {Promise<number>}
     */
    cleanup_stale_streams() {
        const ret = wasm.adb_cleanup_stale_streams(this.__wbg_ptr);
        return ret;
    }
    /**
     * Close an open stream.
     * @param {number} local_id
     * @returns {Promise<void>}
     */
    closeStream(local_id) {
        const ret = wasm.adb_closeStream(this.__wbg_ptr, local_id);
        return ret;
    }
    /**
     * Request device and connect
     * Returns device information as JSON
     * @returns {Promise<any>}
     */
    connect() {
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
        const ret = wasm.adb_connectWithUsbDevice(this.__wbg_ptr, usb_device);
        return ret;
    }
    /**
     * Create a directory (with parent directories)
     * @param {string} remote_path
     * @returns {Promise<void>}
     */
    create_directory(remote_path) {
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
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_download_bugreport(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Get device properties
     * @returns {Promise<any>}
     */
    get_properties() {
        const ret = wasm.adb_get_properties(this.__wbg_ptr);
        return ret;
    }
    /**
     * Check device health
     * @returns {Promise<boolean>}
     */
    health_check() {
        const ret = wasm.adb_health_check(this.__wbg_ptr);
        return ret;
    }
    /**
     * Check if connected
     * @returns {boolean}
     */
    is_connected() {
        const ret = wasm.adb_is_connected(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * List available bugreports on device
     * Returns array of file paths
     * @returns {Promise<any>}
     */
    list_bugreports() {
        const ret = wasm.adb_list_bugreports(this.__wbg_ptr);
        return ret;
    }
    /**
     * List directory contents
     * @param {string} path
     * @returns {Promise<any>}
     */
    list_directory(path) {
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
        const ret = wasm.adb_logcat(this.__wbg_ptr, lines);
        return ret;
    }
    /**
     * Clear logcat buffer
     * @returns {Promise<void>}
     */
    logcat_clear() {
        const ret = wasm.adb_logcat_clear(this.__wbg_ptr);
        return ret;
    }
    /**
     * Create a new ADB instance
     */
    constructor() {
        const ret = wasm.adb_new();
        this.__wbg_ptr = ret;
        AdbFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Open an arbitrary ADB stream (e.g. `localabstract:goauld-agent-1234`).
     * Returns the local stream id used with `write_stream` / `read_stream` / `close_stream`.
     *
     * Takes the inner client across `.await` so wasm-bindgen does not hold `&mut self`
     * for the whole USB wait (avoids "recursive use of an object" on overlapping calls).
     * @param {string} destination
     * @returns {Promise<number>}
     */
    openStream(destination) {
        const ptr0 = passStringToWasm0(destination, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_openStream(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Pull a file from the device
     * Returns the file data as a Uint8Array
     * @param {string} path
     * @returns {Promise<Uint8Array>}
     */
    pull_file(path) {
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
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(remote_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.adb_push_file(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Read the next WRTE payload for a stream. Rejects when the stream is closed.
     * @param {number} local_id
     * @returns {Promise<Uint8Array>}
     */
    readStream(local_id) {
        const ret = wasm.adb_readStream(this.__wbg_ptr, local_id);
        return ret;
    }
    /**
     * Reboot the device
     * target can be "bootloader", "recovery", or null for normal reboot
     * @param {string | null} [target]
     * @returns {Promise<void>}
     */
    reboot(target) {
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
        const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_shell_with_timeout(this.__wbg_ptr, ptr0, len0, timeout_ms);
        return ret;
    }
    /**
     * Get file statistics
     * @param {string} path
     * @returns {Promise<any>}
     */
    stat_file(path) {
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_stat_file(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Write bytes to an open stream.
     * @param {number} local_id
     * @param {Uint8Array} data
     * @returns {Promise<void>}
     */
    writeStream(local_id, data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.adb_writeStream(this.__wbg_ptr, local_id, ptr0, len0);
        return ret;
    }
}
if (Symbol.dispose) Adb.prototype[Symbol.dispose] = Adb.prototype.free;

export class JsDeviceInfo {
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
        const ret = wasm.jsdeviceinfo_product_id(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string | undefined}
     */
    get serial() {
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
        const ret = wasm.jsdeviceinfo_vendor_id(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) JsDeviceInfo.prototype[Symbol.dispose] = JsDeviceInfo.prototype.free;

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
 * Remove stored keypair
 */
export function remove_keypair() {
    const ret = wasm.remove_keypair();
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_bce6d499ff0a4aff: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_debug_string_edece8177ad01481: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_5cd60d5cf78b4eef: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_b4593df85baada48: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_dde0fd9020db4434: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_35bb9f4c7fd651d5: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_9c31b086c2b26051: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_3fa391f3fcdb55f8: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_alternates_94bdc04f73e55d56: function(arg0) {
            const ret = arg0.alternates;
            return ret;
        },
        __wbg_buffer_297793a8f3a42542: function(arg0) {
            const ret = arg0.buffer;
            return ret;
        },
        __wbg_call_dfde26266607c996: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_claimInterface_a478c68e83014069: function(arg0, arg1) {
            const ret = arg0.claimInterface(arg1);
            return ret;
        },
        __wbg_close_ec94b118fe7ba09b: function(arg0) {
            const ret = arg0.close();
            return ret;
        },
        __wbg_configurationValue_8e222ca80320c965: function(arg0) {
            const ret = arg0.configurationValue;
            return ret;
        },
        __wbg_configuration_e183fe9822282224: function(arg0) {
            const ret = arg0.configuration;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_configurations_2cebe04267acccf8: function(arg0) {
            const ret = arg0.configurations;
            return ret;
        },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_data_05d1aaced2f58174: function(arg0) {
            const ret = arg0.data;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_debug_83758bc0b77ada71: function(arg0) {
            console.debug(arg0);
        },
        __wbg_direction_ee2cbcfc5d0bdc25: function(arg0) {
            const ret = arg0.direction;
            return (__wbindgen_enum_UsbDirection.indexOf(ret) + 1 || 3) - 1;
        },
        __wbg_endpointNumber_ec01f5054ad5c233: function(arg0) {
            const ret = arg0.endpointNumber;
            return ret;
        },
        __wbg_endpoints_d8be4700ee2c4ce7: function(arg0) {
            const ret = arg0.endpoints;
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_error_f085d7e62279b703: function(arg0) {
            console.error(arg0);
        },
        __wbg_getItem_88cc26174f98c20c: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getItem(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_98fdf51d029a75eb: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_info_d2226ca1698bd09c: function(arg0) {
            console.info(arg0);
        },
        __wbg_instanceof_Promise_09012cfa9708520a: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Promise;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbAlternateInterface_6ad6a252b017916f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBAlternateInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbConfiguration_6991c09002c1d59b: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBConfiguration;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbDevice_4feb560b857ef5fb: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBDevice;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbEndpoint_c5fb86600183192d: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBEndpoint;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbInTransferResult_f2e8a8949d66f47f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBInTransferResult;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbInterface_ddda594a94e153b5: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbOutTransferResult_c2a6d00c5fca2a44: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBOutTransferResult;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_faa5cf994f49cca7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_interfaceClass_8f95b9ac7bc5b9c6: function(arg0) {
            const ret = arg0.interfaceClass;
            return ret;
        },
        __wbg_interfaceNumber_62ba0473572be6fa: function(arg0) {
            const ret = arg0.interfaceNumber;
            return ret;
        },
        __wbg_interfaceProtocol_75635fc73e98a0fa: function(arg0) {
            const ret = arg0.interfaceProtocol;
            return ret;
        },
        __wbg_interfaceSubclass_e6a230026ff7eccf: function(arg0) {
            const ret = arg0.interfaceSubclass;
            return ret;
        },
        __wbg_interfaces_a501b51c95afbf16: function(arg0) {
            const ret = arg0.interfaces;
            return ret;
        },
        __wbg_length_2591a0f4f659a55c: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_56fcd3e2b7e0299d: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_localStorage_e3f4a792bb36c514: function() { return handleError(function (arg0) {
            const ret = arg0.localStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_log_eb752234eec406d1: function(arg0) {
            console.log(arg0);
        },
        __wbg_manufacturerName_d080cd0b82266874: function(arg0, arg1) {
            const ret = arg1.manufacturerName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_navigator_3db7ba343e05d4d1: function(arg0) {
            const ret = arg0.navigator;
            return ret;
        },
        __wbg_new_02d162bc6cf02f60: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_070df68d66325372: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_310879b66b6e95e1: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_7ddec6de44ff8f5d: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_from_slice_269e35316ed2d061: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_c072c4ce9a2a0cdf: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined_______true_(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_length_99887c91eae4abab: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_81363d44c96dd239: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_open_4037db279adef6c3: function(arg0) {
            const ret = arg0.open();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_productId_dbfc0d6739f5c227: function(arg0) {
            const ret = arg0.productId;
            return ret;
        },
        __wbg_productName_3f922a38aebeb6f9: function(arg0, arg1) {
            const ret = arg1.productName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_prototypesetcall_5f9bdc8d75e07276: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_queueMicrotask_78d584b53af520f5: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_b39ea83c7f01971a: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_releaseInterface_47d0c18273d6b284: function(arg0, arg1) {
            const ret = arg0.releaseInterface(arg1);
            return ret;
        },
        __wbg_removeItem_9b48e0e4faf386fc: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_requestDevice_14fad17e6427d309: function(arg0, arg1) {
            const ret = arg0.requestDevice(arg1);
            return ret;
        },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_d17db9352f5a220e: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_selectConfiguration_d7315c2ffd482814: function(arg0, arg1) {
            const ret = arg0.selectConfiguration(arg1);
            return ret;
        },
        __wbg_serialNumber_8b748f888f888f5e: function(arg0, arg1) {
            const ret = arg1.serialNumber;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_setItem_caab843cd6845dbb: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_78ea6a19f4818587: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_class_code_163e2d9117ad7bd0: function(arg0, arg1) {
            arg0.classCode = arg1;
        },
        __wbg_set_facb7a5914e0fa39: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_filters_236148ba20e7da3e: function(arg0, arg1, arg2) {
            arg0.filters = getArrayJsValueViewFromWasm0(arg1, arg2);
        },
        __wbg_set_protocol_code_7f74949ac0c0e1fa: function(arg0, arg1) {
            arg0.protocolCode = arg1;
        },
        __wbg_set_subclass_code_f001d69e25f11576: function(arg0, arg1) {
            arg0.subclassCode = arg1;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_9b2406c23aeb2023: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_b34d2126934e16ba: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_status_2858b5291a2e6c7f: function(arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
        },
        __wbg_status_e96eba8e694fbf18: function(arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
        },
        __wbg_subarray_7c6a0da8f3b4a1ba: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_then_837494e384b37459: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_then_bd927500e8905df2: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_transferIn_0ae604624bd0d715: function(arg0, arg1, arg2) {
            const ret = arg0.transferIn(arg1, arg2 >>> 0);
            return ret;
        },
        __wbg_transferOut_d6340c8b1e70ef1f: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transferOut(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_usb_753b2e4a3ac9a6a8: function(arg0) {
            const ret = arg0.usb;
            return ret;
        },
        __wbg_vendorId_c3454053ee5edafc: function(arg0) {
            const ret = arg0.vendorId;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_warn_c4e0780980765a86: function(arg0) {
            console.warn(arg0);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 289, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___JsValue__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBDevice")], shim_idx: 6, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBInTransferResult")], shim_idx: 6, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__2);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("USBOutTransferResult")], shim_idx: 6, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__3);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("undefined")], shim_idx: 6, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__4);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000008: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
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
        "./webadb_rs_bg.js": import0,
    };
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___JsValue__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___JsValue__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__2(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__2(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__3(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__3(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__4(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___wasm_bindgen_a35db4cae15c1709___sys__Undefined__core_9b3796e30d99ddb7___result__Result_____wasm_bindgen_a35db4cae15c1709___JsError___true__4(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined_______true_(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen_a35db4cae15c1709___convert__closures_____invoke___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined___js_sys_36e8e35f3452e850___Function_fn_wasm_bindgen_a35db4cae15c1709___JsValue_____wasm_bindgen_a35db4cae15c1709___sys__Undefined_______true_(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_UsbDirection = ["in", "out"];


const __wbindgen_enum_UsbTransferStatus = ["ok", "stall", "babble"];
const AdbFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_adb_free(ptr, 1));
const JsDeviceInfoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_jsdeviceinfo_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
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
    return decodeText(ptr >>> 0, len);
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

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
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
        module_or_path = new URL('webadb_rs_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };

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
     * @param {Uint8Array} data
     * @param {string} rules
     * @returns {Promise<any>}
     */
    analyze_bugreport(data, rules) {
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
     * Request device and connect
     * Returns device information as JSON
     * @returns {Promise<any>}
     */
    connect() {
        const ret = wasm.adb_connect(this.__wbg_ptr);
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
     * Get full bugreport data as JSON for inspection
     * @param {Uint8Array} data
     * @returns {Promise<any>}
     */
    get_bugreport_full_data(data) {
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
}
if (Symbol.dispose) Adb.prototype[Symbol.dispose] = Adb.prototype.free;

/**
 * Device information for JavaScript
 */
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

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_8c4e43fe74559d73: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_String_8f0eb39a4a4c2f66: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_debug_string_0bc8482c6e3508ae: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_0095a73b8b156f76: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_cd444516edc5b180: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_9e4d92534c42d778: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_d9b87ff7982e3b21: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_alternates_e0d9338866b4dca8: function(arg0) {
            const ret = arg0.alternates;
            return ret;
        },
        __wbg_buffer_b5233aedbb1a6778: function(arg0) {
            const ret = arg0.buffer;
            return ret;
        },
        __wbg_call_389efe28435a9388: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_4708e0c13bdc8e95: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_claimInterface_bc779477cbda6491: function(arg0, arg1) {
            const ret = arg0.claimInterface(arg1);
            return ret;
        },
        __wbg_close_2172ab63df4e6ce2: function(arg0) {
            const ret = arg0.close();
            return ret;
        },
        __wbg_configuration_472a1cdf5f9a2a03: function(arg0) {
            const ret = arg0.configuration;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_crypto_86f2631e91b51511: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_data_d25c73d3e55fbeec: function(arg0) {
            const ret = arg0.data;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_debug_a4099fa12db6cd61: function(arg0) {
            console.debug(arg0);
        },
        __wbg_direction_2dc8fc1c97af2d49: function(arg0) {
            const ret = arg0.direction;
            return (__wbindgen_enum_UsbDirection.indexOf(ret) + 1 || 3) - 1;
        },
        __wbg_endpointNumber_4419ea4b52726ed5: function(arg0) {
            const ret = arg0.endpointNumber;
            return ret;
        },
        __wbg_endpoints_8f0ba58e16948a8b: function(arg0) {
            const ret = arg0.endpoints;
            return ret;
        },
        __wbg_error_7534b8e9a36f1ab4: function(arg0, arg1) {
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
        __wbg_error_9a7fe3f932034cde: function(arg0) {
            console.error(arg0);
        },
        __wbg_getItem_0c792d344808dcf5: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg1.getItem(getStringFromWasm0(arg2, arg3));
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        }, arguments); },
        __wbg_getRandomValues_b3f15fcbfabb0f8b: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_9b94d73e6221f75c: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_info_148d043840582012: function(arg0) {
            console.info(arg0);
        },
        __wbg_instanceof_UsbAlternateInterface_2addc0620aaaed1f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBAlternateInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbDevice_1f2f02e8a6de60fb: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBDevice;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbEndpoint_3b36468525642d43: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBEndpoint;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbInTransferResult_1d9e31f6c96ed125: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBInTransferResult;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbInterface_6ded3c3734f0a57f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBInterface;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_UsbOutTransferResult_53748b93b796f365: function(arg0) {
            let result;
            try {
                result = arg0 instanceof USBOutTransferResult;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_ed49b2db8df90359: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_interfaceClass_f34fe009ad9e0a3b: function(arg0) {
            const ret = arg0.interfaceClass;
            return ret;
        },
        __wbg_interfaceNumber_56feb61466f20b21: function(arg0) {
            const ret = arg0.interfaceNumber;
            return ret;
        },
        __wbg_interfaceProtocol_ccffe6313c38d8b8: function(arg0) {
            const ret = arg0.interfaceProtocol;
            return ret;
        },
        __wbg_interfaceSubclass_f1222859bc9c7f6a: function(arg0) {
            const ret = arg0.interfaceSubclass;
            return ret;
        },
        __wbg_interfaces_1996402d251842c0: function(arg0) {
            const ret = arg0.interfaces;
            return ret;
        },
        __wbg_length_32ed9a279acd054c: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_35a7bace40f36eac: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_localStorage_a22d31b9eacc4594: function() { return handleError(function (arg0) {
            const ret = arg0.localStorage;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_log_6b5ca2e6124b2808: function(arg0) {
            console.log(arg0);
        },
        __wbg_manufacturerName_a7d32f2031298eef: function(arg0, arg1) {
            const ret = arg1.manufacturerName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_msCrypto_d562bbe83e0d4b91: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_navigator_43be698ba96fc088: function(arg0) {
            const ret = arg0.navigator;
            return ret;
        },
        __wbg_new_361308b2356cecd0: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_3eb36ae241fe6f44: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_8a6f238a6ece86ea: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_b5d9e2fb389fef91: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h33cafa42f5786487(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = state0.b = 0;
            }
        },
        __wbg_new_dca287b076112a51: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_dd2b680c8bf6ae29: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_from_slice_a3d2629dc1826784: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_no_args_1c7c842f08d00ebb: function(arg0, arg1) {
            const ret = new Function(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_with_length_a2c39cbe88fd8ff1: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_e1f24f89a7336c2e: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_a3af9a2f4bbaa4d1: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_now_ebffdf7e580f210d: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_open_22ea7a40936296c3: function(arg0) {
            const ret = arg0.open();
            return ret;
        },
        __wbg_performance_06f12ba62483475d: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_process_3975fd6c72f520aa: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_productId_be33b73d4ab92af2: function(arg0) {
            const ret = arg0.productId;
            return ret;
        },
        __wbg_productName_6f83dc408138ce17: function(arg0, arg1) {
            const ret = arg1.productName;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_8ffdcb2063340ba5: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_queueMicrotask_0aa0a927f78f5d98: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_5bb536982f78a56f: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_randomFillSync_f8c153b79f285817: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_releaseInterface_7d4b1d4fffe4b998: function(arg0, arg1) {
            const ret = arg0.releaseInterface(arg1);
            return ret;
        },
        __wbg_removeItem_f6369b1a6fa39850: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.removeItem(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_requestDevice_67428738a7f1c90c: function(arg0, arg1) {
            const ret = arg0.requestDevice(arg1);
            return ret;
        },
        __wbg_require_b74f47fc2d022fd6: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_002c4b7d9d8f6b64: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_serialNumber_60b84039e4432475: function(arg0, arg1) {
            const ret = arg1.serialNumber;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_setItem_cf340bb2edbd3089: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            arg0.setItem(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
        }, arguments); },
        __wbg_set_1eb0999cf5d27fc8: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_3f1d0b984ed272ed: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_class_code_79fa8786f105b242: function(arg0, arg1) {
            arg0.classCode = arg1;
        },
        __wbg_set_f43e577aea94465b: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_filters_c03f91c2230b136e: function(arg0, arg1) {
            arg0.filters = arg1;
        },
        __wbg_set_protocol_code_d0b3fa081a75c251: function(arg0, arg1) {
            arg0.protocolCode = arg1;
        },
        __wbg_set_subclass_code_4418c4f12fbeb444: function(arg0, arg1) {
            arg0.subclassCode = arg1;
        },
        __wbg_stack_0ed75d68575b0f3c: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_12837167ad935116: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_a621d3dfbb60d0ce: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f8727f0cf888e0bd: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_status_01359a987386b7e7: function(arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
        },
        __wbg_status_285842025c8f54fb: function(arg0) {
            const ret = arg0.status;
            return (__wbindgen_enum_UsbTransferStatus.indexOf(ret) + 1 || 4) - 1;
        },
        __wbg_subarray_a96e1fef17ed23cb: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_then_0d9fe2c7b1857d32: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_b9e7b3b5f1a9e1b5: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_transferIn_161bfc761703891b: function(arg0, arg1, arg2) {
            const ret = arg0.transferIn(arg1, arg2 >>> 0);
            return ret;
        },
        __wbg_transferOut_bfa7cc4bbc6cd69c: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transferOut(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_usb_171a4fd366068af0: function(arg0) {
            const ret = arg0.usb;
            return ret;
        },
        __wbg_vendorId_4e9fbd1efedd7fa6: function(arg0) {
            const ret = arg0.vendorId;
            return ret;
        },
        __wbg_versions_4e31226f5e8dc909: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_warn_f7ae1b2e66ccb930: function(arg0) {
            console.warn(arg0);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 938, function: Function { arguments: [Externref], shim_idx: 939, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__hc65388e24af83a34, wasm_bindgen__convert__closures_____invoke__h43e5be2c4f1d34bf);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
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

function wasm_bindgen__convert__closures_____invoke__h43e5be2c4f1d34bf(arg0, arg1, arg2) {
    wasm.wasm_bindgen__convert__closures_____invoke__h43e5be2c4f1d34bf(arg0, arg1, arg2);
}

function wasm_bindgen__convert__closures_____invoke__h33cafa42f5786487(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h33cafa42f5786487(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_UsbDirection = ["in", "out"];


const __wbindgen_enum_UsbTransferStatus = ["ok", "stall", "babble"];
const AdbFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_adb_free(ptr >>> 0, 1));
const JsDeviceInfoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_jsdeviceinfo_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => state.dtor(state.a, state.b));

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

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
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
            state.dtor(state.a, state.b);
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

/* @ts-self-types="./droid2web.d.ts" */

/**
 * Decompile an entire class to Java source. Returns `{ ok, data?: { name, relative_path, source }, error? }`.
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {any | null} [options]
 * @returns {any}
 */
export function decompile_dex_class(bytes, class_idx, options) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decompile_dex_class(ptr0, len0, class_idx, isLikeNone(options) ? 0 : addToExternrefTable0(options));
    return ret;
}

/**
 * Compare DEX code in two APK/DEX blobs (multi-DEX union, SimHash + LSH matching).
 * Returns transferable UTF-8 JSON `{ok, data?, error?}`.
 * @param {Uint8Array} left
 * @param {string} left_name
 * @param {Uint8Array} right
 * @param {string} right_name
 * @returns {Uint8Array}
 */
export function diff_dex(left, left_name, right, right_name) {
    const ptr0 = passArray8ToWasm0(left, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(left_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(right, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(right_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.diff_dex(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret;
}

/**
 * Field get/put sites for a field_ids index.
 * @param {Uint8Array} bytes
 * @param {number} field_idx
 * @returns {any}
 */
export function find_field_xrefs(bytes, field_idx) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_field_xrefs(ptr0, len0, field_idx);
    return ret;
}

/**
 * Full reverse call traces (root → … → target) for a method.
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @returns {any}
 */
export function find_method_call_traces(bytes, class_idx, method_idx) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_method_call_traces(ptr0, len0, class_idx, method_idx);
    return ret;
}

/**
 * Methods invoked from (class_idx, method_idx).
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @returns {any}
 */
export function find_method_callees(bytes, class_idx, method_idx) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_method_callees(ptr0, len0, class_idx, method_idx);
    return ret;
}

/**
 * Find invoke sites that call the method at (class_idx, method_idx) — same indices as get_dex_method.
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @returns {any}
 */
export function find_method_callers(bytes, class_idx, method_idx) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_method_callers(ptr0, len0, class_idx, method_idx);
    return ret;
}

/**
 * Find `const-string` sites that load the given permission names. `permissions` is a JS string array.
 * @param {Uint8Array} bytes
 * @param {any} permissions
 * @returns {any}
 */
export function find_permission_usages(bytes, permissions) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_permission_usages(ptr0, len0, permissions);
    return ret;
}

/**
 * Find `const-string` sites that load the given string pool index, plus pool file offsets.
 * @param {Uint8Array} bytes
 * @param {number} string_index
 * @returns {any}
 */
export function find_string_usages(bytes, string_index) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.find_string_usages(ptr0, len0, string_index);
    return ret;
}

/**
 * Extract a file from an APK. Returns raw bytes or null.
 * @param {Uint8Array} apk_bytes
 * @param {string} file_name
 * @returns {Uint8Array | undefined}
 */
export function get_apk_file_content(apk_bytes, file_name) {
    const ptr0 = passArray8ToWasm0(apk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(file_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.get_apk_file_content(ptr0, len0, ptr1, len1);
    let v3;
    if (ret[0] !== 0) {
        v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v3;
}

/**
 * Decompile a single DEX method (for use after parse_dex_light). Returns { ok, data?, error? }.
 * Optional 4th argument: `{ renames?, mode?, showBytecode?, useDebugNames?, deobf? }`
 * (legacy bare renames object still works).
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @param {any | null} [options]
 * @returns {any}
 */
export function get_dex_method(bytes, class_idx, method_idx, options) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.get_dex_method(ptr0, len0, class_idx, method_idx, isLikeNone(options) ? 0 : addToExternrefTable0(options));
    return ret;
}

/**
 * Load DEX string pool on demand (after browse parse omitted it).
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function get_dex_strings(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.get_dex_strings(ptr0, len0);
    return ret;
}

/**
 * Return built-in MobHunt Semgrep rules YAML + parsed rule summaries.
 * @returns {any}
 */
export function get_semgrep_builtin_rules() {
    const ret = wasm.get_semgrep_builtin_rules();
    return ret;
}

/**
 * Compact DEX class index (names + method counts only). For APK-wide class lookup without
 * shipping the full light-parse JSON (which freezes the UI on Facebook-scale DEXes).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function index_dex_classes(bytes) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.index_dex_classes(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Same as [`index_dex_classes_js`] but UTF-8 JSON as transferable `Uint8Array`.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function index_dex_classes_bytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.index_dex_classes_bytes(ptr0, len0);
    return ret;
}

export function init() {
    wasm.init();
}

/**
 * Parse APK file. Returns JSON ApkInfo.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_apk(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_apk(ptr0, len0);
    return ret;
}

/**
 * Parse ARSC file. Returns JSON ArscInfo.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_arsc(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_arsc(ptr0, len0);
    return ret;
}

/**
 * Parse `resources.arsc` into id → `R.type.name` map (for decompiler const replacement).
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_arsc_resource_map(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_arsc_resource_map(ptr0, len0);
    return ret;
}

/**
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_arsc_resource_tables(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_arsc_resource_tables(ptr0, len0);
    return ret;
}

/**
 * Parse `resources.arsc` into id → resolved string value (labels, etc.).
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_arsc_resource_values(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_arsc_resource_values(ptr0, len0);
    return ret;
}

/**
 * Parse AXML file. Returns JSON AxmlInfo.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_axml(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_axml(ptr0, len0);
    return ret;
}

/**
 * Parse DEX file. Returns JSON DexInfo.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function parse_dex(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_dex(ptr0, len0);
    return ret;
}

/**
 * Detect file type from magic bytes and parse accordingly.
 * Returns a JSON string of { ok, data?, error? } so JS receives a plain object via JSON.parse.
 * @param {Uint8Array} bytes
 * @param {string} filename
 * @returns {string}
 */
export function parse_file(bytes, filename) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(filename, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.parse_file(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Same as [`parse_file`] but returns UTF-8 JSON as `Uint8Array` for transferable worker results.
 * @param {Uint8Array} bytes
 * @param {string} filename
 * @returns {Uint8Array}
 */
export function parse_file_bytes(bytes, filename) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(filename, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.parse_file_bytes(ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Parse META-INF/MANIFEST.MF, *.SF, or *.RSA|*.DSA|*.EC into structured JSON.
 * @param {string} name
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function parse_meta_inf_file(name, bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.parse_meta_inf_file(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse Semgrep YAML and return rule summaries. Returns `{ ok, rules }` or error.
 * @param {string} yaml
 * @returns {any}
 */
export function parse_semgrep_rules(yaml) {
    const ptr0 = passStringToWasm0(yaml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parse_semgrep_rules(ptr0, len0);
    return ret;
}

/**
 * If `bytes` is an APKM, return the base APK bytes; otherwise return a copy of `bytes`.
 * Call this before storing APK bytes for `get_apk_file_content` / tree extraction.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array | undefined}
 */
export function prepare_apk_bytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.prepare_apk_bytes(ptr0, len0);
    let v2;
    if (ret[0] !== 0) {
        v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v2;
}

/**
 * Run the bytecode emulator on a method. Params: JSON array, e.g. "[]" or "[5, 3]" for int args.
 * Returns { ok, data?: EmulatorRunResult, error? }.
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @param {string} params_json
 * @returns {any}
 */
export function run_dex_emulator(bytes, class_idx, method_idx, params_json) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.run_dex_emulator(ptr0, len0, class_idx, method_idx, ptr1, len1);
    return ret;
}

/**
 * Run the emulator and return full step-by-step history (for step-by-step UI). Params: JSON e.g. "[]" or "[5,3]".
 * max_steps: 0 = run to completion; > 0 = run at most that many steps (for step-by-step execution).
 * @param {Uint8Array} bytes
 * @param {number} class_idx
 * @param {number} method_idx
 * @param {string} params_json
 * @param {number} max_steps
 * @returns {any}
 */
export function run_dex_emulator_with_history(bytes, class_idx, method_idx, params_json, max_steps) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.run_dex_emulator_with_history(ptr0, len0, class_idx, method_idx, ptr1, len1, max_steps);
    return ret;
}

/**
 * Run Semgrep-style rules on a DEX. Optional `rules_yaml` (empty = MobHunt starter).
 * Optional `on_progress` receives findings so far during the scan.
 * @param {Uint8Array} bytes
 * @param {string | null} [rules_yaml]
 * @param {Function | null} [on_progress]
 * @returns {any}
 */
export function scan_semgrep(bytes, rules_yaml, on_progress) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(rules_yaml) ? 0 : passStringToWasm0(rules_yaml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.scan_semgrep(ptr0, len0, ptr1, len1, isLikeNone(on_progress) ? 0 : addToExternrefTable0(on_progress));
    return ret;
}

/**
 * Run Semgrep XML rules (e.g. decoded AndroidManifest.xml).
 * @param {string} xml
 * @param {string} path_label
 * @param {string | null} [rules_yaml]
 * @returns {any}
 */
export function scan_semgrep_xml(xml, path_label, rules_yaml) {
    const ptr0 = passStringToWasm0(xml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(path_label, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(rules_yaml) ? 0 : passStringToWasm0(rules_yaml, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.scan_semgrep_xml(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Run vulnerability detectors (+ PendingIntent) on a DEX. Returns `{ ok, findings }` or `{ ok:false, error }`.
 * Optional `on_progress` receives the findings array so far whenever new detections appear.
 * @param {Uint8Array} bytes
 * @param {Function | null} [on_progress]
 * @returns {any}
 */
export function scan_vulns(bytes, on_progress) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.scan_vulns(ptr0, len0, isLikeNone(on_progress) ? 0 : addToExternrefTable0(on_progress));
    return ret;
}

/**
 * Run Mariana-Trench–style taint solver on a DEX. Returns `{ ok, report }` (IssueReport) or error.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function taint_solve(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.taint_solve(ptr0, len0);
    return ret;
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_fe3709820da6d9f4: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_boolean_get_ff8209d052ce1cc3: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_a1b3fd0656850da8: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_5ba21a357fd4699f: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_function_82aa5b8e9371b250: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_d69c58af0c7ab830: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_61452b678ecf7ecf: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_91960b7ba9d4d76b: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_7b12045c262a3121: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_cfddc78de4a067b0: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_eb70a740eef5cf3a: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_aab6399cd8ec8844: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_83ebd457a191bc2a: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_72a54043615c73e3: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_call_a3e856c036847f30: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_done_f9e33fcfdacdad82: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_95c8dc6ea5bcb5d3: function(arg0) {
            const ret = Object.entries(arg0);
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
        __wbg_get_3c8961765646956e: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_5aaf989b657a0cbd: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_bda2de250e7f67d3: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_unchecked_fb17614cc2ea6bd4: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_5947ef6d17a07122: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_c21f42d2acffa054: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_3bc43738919f4587: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_WorkerGlobalScope_87b85b4d8fb87a62: function(arg0) {
            let result;
            try {
                result = arg0 instanceof WorkerGlobalScope;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_65307171a630ba34: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_iterator_b3054eb88cb59de4: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_length_684e7f4ac265724c: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_a4c11dc94fe5e775: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_log_b269bfcd91b2a70d: function(arg0) {
            console.log(arg0);
        },
        __wbg_new_18cda2e4779f118c: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_2e5db3ea23dcc1a1: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_31d07d7329f84e37: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_5c365a7570baea64: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_from_slice_87b95dbde92b7cc2: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_next_2ae970b266acf6e5: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_6ce141aa72ac5eeb: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_now_7627eff456aa5959: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_performance_40fcb284bdedd70e: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_performance_9c882b05042613aa: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_prototypesetcall_7c3092bff32833dc: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_set_0992bb8f727d2d33: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_c7d56bae406212ae: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_833a66cb4996dbd8: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_fc74cdbdccd80770: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_066699022f35d48b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f821c7eb05393790: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_value_69c16823ba9b4739: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_warn_8df1421c02ba730b: function(arg0) {
            console.warn(arg0);
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
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
        __wbindgen_object_is_undefined: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
    };
    return {
        __proto__: null,
        "./droid2web_bg.js": import0,
    };
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

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
        module_or_path = new URL('droid2web_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };

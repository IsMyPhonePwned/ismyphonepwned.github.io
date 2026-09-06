/**
 * Default goauld scripts for the Device tab (quick testing).
 * Sourced from arm_goauld/scripts/fixtures where noted.
 */

export const SCRIPT_PRESETS = [
  {
    id: 'smoke',
    label: 'Smoke / RPC',
    title: 'rpc.exports ping/echo/add + ready send',
    source: `send({type:'ready', from:'droid2web'});
rpc.exports = {
  echo: function (x) { return x; },
  add: function (a, b) { return a + b; },
  ping: function () { return 'pong'; },
};
`,
  },
  {
    id: 'toast',
    label: 'Toast',
    title: 'Show android.widget.Toast on the main thread',
    source: `// Frida-shaped toast (arm_goauld fixtures/java_toast.js)
Java.perform(function () {
  var context = Java.use("android.app.ActivityThread")
    .currentApplication()
    .getApplicationContext();

  Java.scheduleOnMainThread(function () {
    var toast = Java.use("android.widget.Toast");
    toast
      .makeText(
        context,
        Java.use("java.lang.String").$new("Hello from goauld (android.widget.Toast)"),
        toast.LENGTH_LONG.value
      )
      .show();
  });
});

send("toast-shown");
`,
  },
  {
    id: 'hi',
    label: 'Hi',
    title: 'Minimal send("hi")',
    source: `send("hi");
`,
  },
  {
    id: 'inspect',
    label: 'Inspect',
    title: 'Dump package storage + loaded classes (fixtures/inspect_package.js)',
    source: `// Package inspector (arm_goauld fixtures/inspect_package.js)
Java.perform(function () {
  var MAX = (typeof globalThis.__INSPECT_MAX === 'number') ? globalThis.__INSPECT_MAX : 40;
  var READ_STATICS = globalThis.__INSPECT_STATICS !== false;

  function isFramework(cn) {
    return (
      cn.indexOf('android.') === 0 ||
      cn.indexOf('androidx.') === 0 ||
      cn.indexOf('java.') === 0 ||
      cn.indexOf('javax.') === 0 ||
      cn.indexOf('dalvik.') === 0 ||
      cn.indexOf('kotlin.') === 0 ||
      cn.indexOf('kotlinx.') === 0 ||
      cn.indexOf('com.android.') === 0 ||
      cn.indexOf('sun.') === 0 ||
      cn.indexOf('libcore.') === 0 ||
      cn.indexOf('goauld.') === 0 ||
      cn.charAt(0) === '['
    );
  }

  var storage = Java.dumpAppStorageSync();
  var pkg = storage.package || '';
  var prefix =
    (typeof globalThis.__INSPECT_PREFIX === 'string' && globalThis.__INSPECT_PREFIX.length)
      ? globalThis.__INSPECT_PREFIX
      : pkg;

  send({
    type: 'inspect-meta',
    package: pkg,
    prefix: prefix,
    dataDir: storage.dataDir || null,
    androidVersion: Java.androidVersion,
  });

  send({
    type: 'inspect-storage',
    sharedPrefs: storage.sharedPrefs || {},
    dataDirListing: storage.dataDirListing || [],
  });

  var all = Java.enumerateLoadedClassesSync();
  var matched = [];
  for (var i = 0; i < all.length; i++) {
    var cn = all[i];
    if (isFramework(cn)) continue;
    if (prefix && cn.indexOf(prefix) === 0) matched.push(cn);
  }
  matched.sort();

  send({
    type: 'inspect-classes',
    matched: matched.length,
    totalLoaded: all.length,
    classes: matched.slice(0, MAX),
  });

  var dumped = 0;
  for (var j = 0; j < matched.length && dumped < MAX; j++) {
    var name = matched[j];
    var entry = {
      name: name,
      methods: (function () {
        try { return JSON.parse(__goauld.javaClassMethodsJson(name)); }
        catch (_) { return []; }
      })(),
      fields: Java.enumerateFieldsSync(name),
    };
    if (READ_STATICS) {
      for (var f = 0; f < entry.fields.length; f++) {
        var fd = entry.fields[f];
        if (!fd.isStatic) continue;
        fd.value = Java.readStaticField(name, fd.name);
      }
    }
    send({ type: 'inspect-class', class: entry });
    dumped++;
  }

  send({
    type: 'inspect-ok',
    package: pkg,
    classesMatched: matched.length,
    classesDumped: dumped,
  });
});
`,
  },
  {
    id: 'java-api',
    label: 'Java API',
    title: 'Trace Android/Java APIs via ART ArtMethod::Invoke (embedded agent)',
    source: `// Trace Android / Java APIs (arm_goauld fixtures/trace_java_api.js)
globalThis.__GOAULD_API_FILTER =
  typeof globalThis.__GOAULD_API_FILTER === 'string'
    ? globalThis.__GOAULD_API_FILTER
    : 'android.,androidx.,java.,javax.,com.android.,dalvik.';
globalThis.__GOAULD_API_MAX_EVENTS =
  typeof globalThis.__GOAULD_API_MAX_EVENTS === 'number'
    ? globalThis.__GOAULD_API_MAX_EVENTS
    : 0;

(function () {
  function safeSend(obj) {
    try { send(obj); } catch (e) {}
  }

  var filter = globalThis.__GOAULD_API_FILTER;
  var maxEvents = globalThis.__GOAULD_API_MAX_EVENTS;
  var hookId = 0;
  try {
    hookId = __goauld.traceAndroidApi(String(filter), maxEvents);
  } catch (e) {
    safeSend({ type: 'android-api-err', err: String(e) });
  }

  safeSend({
    type: 'trace-java-ready',
    art_invoke_hook: hookId,
    filter: filter,
    max_events: maxEvents,
  });
  send('java-api-trace-installed');
})();
`,
  },
  {
    id: 'modules',
    label: 'Modules',
    title: 'List Process modules / ranges',
    source: `// Quick Process / Module snapshot
send({
  type: 'process',
  id: Process.id,
  arch: Process.arch,
  platform: Process.platform,
  pageSize: Process.pageSize,
});

var mods = Process.enumerateModules();
send({
  type: 'modules',
  count: mods.length,
  modules: mods.slice(0, 40).map(function (m) {
    return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
  }),
});

send({ type: 'modules-ok' });
`,
  },
  {
    id: 'custom',
    label: 'Custom',
    title: 'Your working script',
    source: '', // filled from editor / last custom
  },
];

/** Build a java/android API trace script with event cap. */
export function buildJavaApiTraceScript({ filter = '', maxEvents = 0 } = {}) {
  const filt =
    (filter && String(filter).trim()) ||
    'android.,androidx.,java.,javax.,com.android.,dalvik.';
  const max = Number(maxEvents) || 0;
  const base = presetById('java-api').source;
  return (
    `globalThis.__GOAULD_API_FILTER = ${JSON.stringify(filt)};\n` +
    `globalThis.__GOAULD_API_MAX_EVENTS = ${max};\n` +
    base.replace(/^globalThis\.__GOAULD_API_FILTER[\s\S]*?globalThis\.__GOAULD_API_MAX_EVENTS[\s\S]*?;\n\n/, '')
  );
}

export function presetById(id) {
  return SCRIPT_PRESETS.find((p) => p.id === id) || SCRIPT_PRESETS[0];
}

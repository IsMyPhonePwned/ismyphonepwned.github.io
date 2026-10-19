/* Readable /proc/meminfo snapshots: summary, grouped counters, zeros collapsed. */
(function () {
    var GROUPS = [
        {
            title: 'RAM and cache',
            keys: ['MemTotal', 'MemFree', 'MemAvailable', 'Buffers', 'Cached', 'Dirty', 'Writeback', 'WritebackTmp', 'Mapped', 'Shmem', 'AnonPages', 'Unevictable', 'Mlocked']
        },
        {
            title: 'Active and inactive',
            keys: ['Active', 'Active(anon)', 'Active(file)', 'Inactive', 'Inactive(anon)', 'Inactive(file)']
        },
        {
            title: 'Swap',
            keys: ['SwapTotal', 'SwapFree', 'SwapCached', 'zram0', 'GpuSwap']
        },
        {
            title: 'Huge pages',
            keys: ['AnonHugePages', 'FileHugePages', 'FilePmdMapped', 'ShmemHugePages', 'ShmemPmdMapped']
        },
        {
            title: 'Kernel',
            keys: ['Slab', 'SReclaimable', 'SUnreclaim', 'KReclaimable', 'KernelStack', 'PageTables', 'SecPageTables', 'Percpu', 'ShadowCallStack', 'VmallocTotal', 'VmallocUsed', 'VmallocChunk', 'Bounce', 'NFS_Unstable']
        },
        {
            title: 'Commit charge',
            hint: 'Virtual address space, not physical RAM.',
            keys: ['CommitLimit', 'Committed_AS']
        },
        {
            title: 'Device memory',
            keys: ['CmaTotal', 'CmaFree', 'GpuTotal', 'DmaHeapPool', 'system', 'system-uncached']
        }
    ];

    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function asKb(v) {
        if (typeof v === 'number' && Number.isFinite(v)) return v;
        if (typeof v === 'string' && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
        return null;
    }

    function formatKb(n) {
        var abs = Math.abs(n);
        if (abs >= 1024 * 1024) {
            var gb = n / (1024 * 1024);
            return (Math.abs(gb) >= 100 ? gb.toFixed(0) : gb.toFixed(2)) + ' GB';
        }
        if (abs >= 1024) {
            var mb = n / 1024;
            return (Math.abs(mb) >= 100 ? mb.toFixed(0) : mb.toFixed(1)) + ' MB';
        }
        return n.toLocaleString() + ' kB';
    }

    function rawKb(n) {
        return n.toLocaleString() + ' kB';
    }

    function row(key, value) {
        var kb = asKb(value);
        var hay = (key + ' ' + (kb == null ? value : formatKb(kb) + ' ' + rawKb(kb))).toLowerCase();
        var main = kb == null ? esc(String(value)) : esc(formatKb(kb));
        var friendly = kb == null ? '' : formatKb(kb);
        var sub = kb == null || friendly.endsWith(' kB') ? '' : '<span class="mem-row__raw">' + esc(rawKb(kb)) + '</span>';
        return '<div class="mem-row" data-mem-item="' + esc(hay) + '"><span class="mem-row__k">' + esc(key) +
            '</span><span class="mem-row__v">' + main + sub + '</span></div>';
    }

    function metric(label, value, extra) {
        return '<div class="mem-metric"><span class="mem-metric__v">' + esc(value) + '</span><span class="mem-metric__k">' +
            esc(label) + '</span>' + (extra ? '<span class="mem-metric__x">' + esc(extra) + '</span>' : '') + '</div>';
    }

    function snapshot(snap, index) {
        var keys = Object.keys(snap || {});
        var used = {};
        var html = '<section class="mem-snap"><h4 class="mem-snap__title">Snapshot ' + (index + 1) + '</h4>';
        var total = asKb(snap.MemTotal);
        var avail = asKb(snap.MemAvailable);
        var free = asKb(snap.MemFree);
        var swapT = asKb(snap.SwapTotal);
        var swapF = asKb(snap.SwapFree);
        var cached = asKb(snap.Cached);
        html += '<div class="mem-metrics">';
        if (total != null) html += metric('Total RAM', formatKb(total), rawKb(total));
        if (avail != null) {
            var pct = total ? Math.round((avail / total) * 100) : null;
            html += metric('Available', formatKb(avail), pct == null ? rawKb(avail) : pct + '% of RAM');
        }
        if (free != null) html += metric('Free', formatKb(free), rawKb(free));
        if (total != null && avail != null) html += metric('In use', formatKb(Math.max(0, total - avail)), rawKb(Math.max(0, total - avail)));
        if (cached != null) html += metric('Cached', formatKb(cached), rawKb(cached));
        if (swapT != null && swapF != null) {
            var swapUsed = Math.max(0, swapT - swapF);
            html += metric('Swap used', formatKb(swapUsed), formatKb(swapT) + ' total');
        }
        html += '</div>';
        if (total && avail != null) {
            var usedPct = Math.max(0, Math.min(100, Math.round(((total - avail) / total) * 100)));
            html += '<div class="mem-bar" role="img" aria-label="' + usedPct + '% of RAM in use"><span style="width:' + usedPct + '%"></span></div>';
            html += '<p class="mem-bar__cap">' + usedPct + '% of RAM in use</p>';
        }

        var zeros = [];
        GROUPS.forEach(function (group) {
            var rows = '';
            group.keys.forEach(function (key) {
                if (!Object.prototype.hasOwnProperty.call(snap, key)) return;
                used[key] = true;
                var kb = asKb(snap[key]);
                if (kb === 0) {
                    zeros.push(key);
                    return;
                }
                rows += row(key, snap[key]);
            });
            if (!rows) return;
            html += '<div class="mem-group"><h5>' + esc(group.title) + '</h5>';
            if (group.hint) html += '<p class="mem-hint">' + esc(group.hint) + '</p>';
            html += '<div class="mem-rows">' + rows + '</div></div>';
        });

        var other = '';
        keys.slice().sort().forEach(function (key) {
            if (used[key]) return;
            var kb = asKb(snap[key]);
            if (kb === 0) {
                zeros.push(key);
                return;
            }
            other += row(key, snap[key]);
        });
        if (other) html += '<div class="mem-group"><h5>Other</h5><div class="mem-rows">' + other + '</div></div>';

        if (zeros.length) {
            html += '<details class="mem-zeros" data-mem-default-open="0"><summary>Zero counters (' + zeros.length + ')</summary><div class="mem-rows">';
            zeros.sort().forEach(function (key) { html += row(key, 0); });
            html += '</div></details>';
        }
        html += '</section>';
        return html;
    }

    window.renderMemoryHtml = function (snaps) {
        var list = Array.isArray(snaps) ? snaps : [];
        if (!list.length) return '';
        return '<div class="search-box mem-search"><span class="search-icon" aria-hidden="true">🔍</span>' +
            '<input type="search" class="mem-filter" placeholder="Filter a counter (MemAvailable, zram, CMA…)" autocomplete="off"></div>' +
            list.map(snapshot).join('');
    };

    window.bindMemoryFilter = function (root) {
        if (!root) return;
        var input = root.querySelector('.mem-filter');
        if (!input || input.dataset.memBound) return;
        input.dataset.memBound = '1';
        input.addEventListener('input', function () {
            var q = input.value.trim().toLowerCase();
            var first = null;
            root.querySelectorAll('.mem-snap').forEach(function (snap) {
                var any = !q;
                snap.querySelectorAll('[data-mem-item]').forEach(function (node) {
                    var hit = !q || (node.getAttribute('data-mem-item') || '').indexOf(q) >= 0;
                    node.hidden = !hit;
                    if (hit) {
                        any = true;
                        if (q && !first) first = node;
                        if (q) {
                            var det = node.closest('details');
                            if (det) det.open = true;
                        }
                    }
                });
                snap.hidden = q ? !any : false;
                if (!q) {
                    snap.querySelectorAll('details[data-mem-default-open]').forEach(function (d) {
                        d.open = d.getAttribute('data-mem-default-open') === '1';
                    });
                }
            });
            if (q && first && first.scrollIntoView) first.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        });
    };
})();

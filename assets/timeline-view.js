/**
 * Visual timeline (elfbrowser-inspired): density canvas, drag-to-zoom, scroll zoom,
 * dual range sliders, plus search & category filters. Used by Android + iPhone.
 */
(function (global) {
    'use strict';

    var DEFAULT_LABELS = {
        searchPlaceholder: 'Search timeline (message, parser, JSON fields)…',
        searchAriaLabel: 'Filter timeline events by text',
        all: 'All',
        detailTitle: 'Event detail',
        hintClick:
            'Click an event for full JSON. Use the search box under the hint to find text inside the selected event. Hover a category chip to highlight that group on the band and overview; hover a list row for one event.',
        detailSearchPlaceholder: 'Search inside this event…',
        detailSearchMatches: '{cur} / {total} matches',
        detailSearchZero: 'No matches in this event',
        detailSearchPrev: 'Previous match',
        detailSearchNext: 'Next match',
        showing: 'Showing {shown} of {filtered} in the time window ({total} after search/category).',
        capped: 'List limited to {max} rows — narrow filters or the time window.',
        approx: 'approx.',
        bindingSnapshot: 'dumpstate capture',
        bindingSystemFallback: 'export clock',
        noMatch: 'No events match.',
        vizHint:
            'Hover a category chip (e.g. VPN) to highlight all its events on the band and overview · Hover a list row for one time · Zoom the visible window to separate nearby events · Drag · Wheel · +/− · Shift+drag pans · Double-click fits full filtered range',
        fitWindow: 'Fit full range',
        windowLabel: 'Visible window',
        windowFrom: 'Start',
        windowTo: 'End',
        rangeStart: 'Window start',
        rangeEnd: 'Window end',
        zoomIn: 'Zoom in',
        zoomOut: 'Zoom out',
        zoomRangeTitle: 'Time range & zoom',
        zoomDetail: 'Detail level (narrow window)',
        zoomBrushHelp: 'Overview of filtered events — click to center the visible window on that time.',
    };

    function stringHash(s) {
        var h = 0;
        var str = String(s);
        for (var i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
        return Math.abs(h);
    }

    function categoryColor(cat, dark, flashy) {
        var hue = stringHash(String(cat)) % 360;
        if (flashy) {
            if (dark) return 'hsl(' + hue + ' 100% 68%)';
            return 'hsl(' + hue + ' 92% 52%)';
        }
        if (dark) return 'hsl(' + hue + ' 50% 52%)';
        return 'hsl(' + hue + ' 55% 38%)';
    }

    function parseIsoMs(s) {
        if (typeof s !== 'string' || !s.trim()) return null;
        var t = Date.parse(s.trim());
        if (!isNaN(t)) return t;
        var t2 = Date.parse(s.trim().replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, '$1T$2'));
        if (!isNaN(t2)) return t2;
        return null;
    }

    /** Timesketch / Plaso uses epoch microseconds; JSON may use number or string (bigint-safe). */
    function numericTimestampToMs(t) {
        if (t == null) return null;
        if (typeof t === 'string') {
            var d = t.trim().replace(/\s/g, '');
            if (!/^\d+$/.test(d)) return null;
            if (typeof BigInt !== 'undefined') {
                try {
                    var bi = BigInt(d);
                    if (bi >= 1000000000000000) return Number(bi / 1000n);
                    if (bi >= 1000000000000n) return Number(bi);
                    if (bi >= 1000000000n) return Number(bi * 1000n);
                } catch (e) {
                    /* fall through */
                }
            }
            t = parseInt(d, 10);
        }
        if (typeof t !== 'number' || !isFinite(t)) return null;
        if (t >= 6e14) return Math.floor(t / 1000);
        if (t >= 1e11) return Math.floor(t);
        if (t >= 1e9) return Math.floor(t * 1000);
        return null;
    }

    function eventTimeMs(ev) {
        if (!ev || typeof ev !== 'object') return null;
        var iso = parseIsoMs(ev.datetime) || parseIsoMs(ev.time);
        if (iso != null) return iso;
        if (ev.timestamp != null) return numericTimestampToMs(ev.timestamp);
        return null;
    }

    function eventMessage(ev) {
        if (!ev || typeof ev !== 'object') return '';
        if (typeof ev.message === 'string' && ev.message.trim()) return ev.message.trim();
        if (typeof ev.content === 'string' && ev.content.trim()) return ev.content.trim();
        return '';
    }

    function defaultCategory(ev) {
        if (!ev || typeof ev !== 'object') return 'event';
        if (ev.bugreport_parser != null && String(ev.bugreport_parser)) return String(ev.bugreport_parser);
        if (ev.sysdiagnose_parser != null && String(ev.sysdiagnose_parser)) return String(ev.sysdiagnose_parser);
        if (ev.il_parser != null && String(ev.il_parser)) return String(ev.il_parser);
        if (ev.category != null && String(ev.category)) return String(ev.category);
        if (ev.event_type != null && String(ev.event_type)) return String(ev.event_type);
        if (ev.timestamp_desc != null && String(ev.timestamp_desc)) return String(ev.timestamp_desc);
        return 'event';
    }

    function escapeHtml(t) {
        if (t == null) return '';
        var el = document.createElement('div');
        el.textContent = String(t);
        return el.innerHTML;
    }

    function fmtLocal(ms) {
        try {
            return new Date(ms).toLocaleString(undefined, {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            });
        } catch (e) {
            return '—';
        }
    }

    /** Calendar context for the visible window (weekday + full date + time). */
    function fmtDateContext(ms) {
        try {
            return new Date(ms).toLocaleString(undefined, {
                weekday: 'short',
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            });
        } catch (e) {
            return '—';
        }
    }

    function humanDuration(ms) {
        if (!isFinite(ms) || ms < 0) return '—';
        var sec = Math.round(ms / 1000);
        if (sec < 120) return sec + ' s';
        var min = Math.round(sec / 60);
        if (min < 120) return min + ' min';
        var hr = Math.floor(min / 60);
        var m = min % 60;
        if (hr < 48) return hr + ' h' + (m ? ' ' + m + ' min' : '');
        var d = Math.floor(hr / 24);
        var h = hr % 24;
        return d + ' d' + (h ? ' ' + h + ' h' : '');
    }

    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function mount(host, opts) {
        if (!host) return;
        var events = (opts && opts.events) || [];
        if (!Array.isArray(events)) events = [];
        var labels = Object.assign({}, DEFAULT_LABELS);
        var rawLb = (opts && opts.labels) || {};
        for (var lk in rawLb) {
            if (rawLb[lk] !== undefined && rawLb[lk] !== null && rawLb[lk] !== '') {
                labels[lk] = rawLb[lk];
            }
        }
        var categoryField = opts && opts.categoryField;
        var getCategory =
            opts && typeof opts.getCategory === 'function'
                ? opts.getCategory
                : function (ev) {
                      if (categoryField && ev && ev[categoryField] != null) return String(ev[categoryField]);
                      return defaultCategory(ev);
                  };
        var maxRender = (opts && opts.maxRender) || 12000;
        var flashy = !(opts && opts.flashyColors === false);
        var vizH = 128;

        function isDark() {
            return document.documentElement.getAttribute('data-theme') === 'dark';
        }

        function catCol(cat) {
            return categoryColor(cat, isDark(), flashy);
        }

        host.textContent = '';

        /** Pre-lowercased JSON for search (avoids JSON.stringify per keystroke). */
        var enriched = [];
        for (var i = 0; i < events.length; i++) {
            var ev = events[i];
            if (!ev || typeof ev !== 'object') continue;
            var tms = eventTimeMs(ev);
            if (tms == null || !isFinite(tms)) continue;
            var cat = getCategory(ev);
            var msg = eventMessage(ev);
            if (!msg) msg = '(' + cat + ')';
            var jtxt = '';
            try {
                jtxt = JSON.stringify(ev).toLowerCase();
            } catch (err) {
                jtxt = '';
            }
            enriched.push({ ev: ev, tms: tms, cat: cat, msg: msg, jtxt: jtxt });
        }
        enriched.sort(function (a, b) {
            return a.tms - b.tms || a.msg.localeCompare(b.msg);
        });

        var cats = {};
        for (var j = 0; j < enriched.length; j++) {
            cats[enriched[j].cat] = (cats[enriched[j].cat] || 0) + 1;
        }
        var catList = Object.keys(cats).sort();

        var toolbar = document.createElement('div');
        toolbar.className = 'timeline-sk-toolbar';
        var search = document.createElement('input');
        search.type = 'search';
        search.className = 'timeline-sk-search';
        search.placeholder = labels.searchPlaceholder;
        search.setAttribute('autocomplete', 'off');
        search.setAttribute('aria-label', labels.searchAriaLabel || labels.searchPlaceholder);
        toolbar.appendChild(search);

        var chipRow = document.createElement('div');
        chipRow.className = 'timeline-sk-chips';
        var chipAll = document.createElement('button');
        chipAll.type = 'button';
        chipAll.className = 'timeline-sk-chip timeline-sk-chip-active';
        chipAll.textContent = labels.all;
        chipAll.dataset.cat = '';
        chipRow.appendChild(chipAll);
        for (var c = 0; c < catList.length; c++) {
            var ch = document.createElement('button');
            ch.type = 'button';
            ch.className = 'timeline-sk-chip';
            ch.textContent = catList[c] + ' (' + cats[catList[c]] + ')';
            ch.dataset.cat = catList[c];
            ch.style.borderLeft = '4px solid ' + catCol(catList[c]);
            chipRow.appendChild(ch);
        }
        toolbar.appendChild(chipRow);
        host.appendChild(toolbar);
        chipRow.querySelectorAll('button.timeline-sk-chip').forEach(function (chipBtn) {
            chipBtn.addEventListener('pointerenter', function () {
                var c = chipBtn.dataset.cat != null ? String(chipBtn.dataset.cat) : '';
                chipHoverCat = c === '' ? null : c;
                requestVizPaint();
            });
            chipBtn.addEventListener('pointerleave', function () {
                chipHoverCat = null;
                requestVizPaint();
            });
        });
        if (flashy) host.classList.add('timeline-sk-flashy');

        var meta = document.createElement('p');
        meta.className = 'timeline-sk-meta';
        host.appendChild(meta);

        var vizWrap = document.createElement('div');
        vizWrap.className = 'timeline-sk-viz-wrap';
        var vizHint = document.createElement('p');
        vizHint.className = 'timeline-sk-viz-hint';
        vizHint.textContent = labels.vizHint;
        vizWrap.appendChild(vizHint);

        var canvasWrap = document.createElement('div');
        canvasWrap.className = 'timeline-sk-canvas-wrap';
        var canvas = document.createElement('canvas');
        canvas.className = 'timeline-sk-canvas';
        canvas.height = vizH;
        var selectionEl = document.createElement('div');
        selectionEl.className = 'timeline-sk-selection';
        selectionEl.style.display = 'none';
        canvasWrap.appendChild(canvas);
        canvasWrap.appendChild(selectionEl);
        vizWrap.appendChild(canvasWrap);

        var ctrlRow = document.createElement('div');
        ctrlRow.className = 'timeline-sk-viz-controls';
        var btnFit = document.createElement('button');
        btnFit.type = 'button';
        btnFit.className = 'timeline-sk-btn-fit';
        btnFit.textContent = labels.fitWindow;
        var btnZoomIn = document.createElement('button');
        btnZoomIn.type = 'button';
        btnZoomIn.className = 'timeline-sk-btn-zoom timeline-sk-btn-zoom-in';
        btnZoomIn.setAttribute('title', labels.zoomIn);
        btnZoomIn.textContent = '＋';
        var btnZoomOut = document.createElement('button');
        btnZoomOut.type = 'button';
        btnZoomOut.className = 'timeline-sk-btn-zoom timeline-sk-btn-zoom-out';
        btnZoomOut.setAttribute('title', labels.zoomOut);
        btnZoomOut.textContent = '−';
        var winSpan = document.createElement('span');
        winSpan.className = 'timeline-sk-window-text';
        ctrlRow.appendChild(btnFit);
        ctrlRow.appendChild(btnZoomIn);
        ctrlRow.appendChild(btnZoomOut);
        ctrlRow.appendChild(winSpan);
        vizWrap.appendChild(ctrlRow);
        var winDatesRow = document.createElement('div');
        winDatesRow.className = 'timeline-sk-window-dates';
        winDatesRow.setAttribute('aria-live', 'polite');
        vizWrap.appendChild(winDatesRow);
        host.appendChild(vizWrap);

        var split = document.createElement('div');
        split.className = 'timeline-sk-split';
        var listWrap = document.createElement('div');
        listWrap.className = 'timeline-sk-list-wrap';
        var listEl = document.createElement('div');
        listEl.className = 'timeline-sk-list';
        listWrap.appendChild(listEl);

        var detail = document.createElement('div');
        detail.className = 'timeline-sk-detail';
        var detailTitleEl = document.createElement('div');
        detailTitleEl.className = 'timeline-sk-detail-title';
        detailTitleEl.textContent = labels.detailTitle;
        var detailHintEl = document.createElement('p');
        detailHintEl.className = 'timeline-sk-detail-hint';
        detailHintEl.textContent = labels.hintClick;
        var detailSearchRow = document.createElement('div');
        detailSearchRow.className = 'timeline-sk-detail-search-row';
        var detailSearch = document.createElement('input');
        detailSearch.type = 'search';
        detailSearch.className = 'timeline-sk-detail-search';
        detailSearch.placeholder = labels.detailSearchPlaceholder || '';
        detailSearch.setAttribute('autocomplete', 'off');
        detailSearch.setAttribute(
            'aria-label',
            labels.detailSearchPlaceholder || 'Search in selected event JSON'
        );
        var btnDetailPrev = document.createElement('button');
        btnDetailPrev.type = 'button';
        btnDetailPrev.className = 'timeline-sk-detail-hit-btn timeline-sk-detail-hit-prev';
        btnDetailPrev.textContent = '‹';
        btnDetailPrev.setAttribute('title', labels.detailSearchPrev || 'Previous');
        btnDetailPrev.setAttribute('aria-label', labels.detailSearchPrev || 'Previous match');
        btnDetailPrev.disabled = true;
        var btnDetailNext = document.createElement('button');
        btnDetailNext.type = 'button';
        btnDetailNext.className = 'timeline-sk-detail-hit-btn timeline-sk-detail-hit-next';
        btnDetailNext.textContent = '›';
        btnDetailNext.setAttribute('title', labels.detailSearchNext || 'Next');
        btnDetailNext.setAttribute('aria-label', labels.detailSearchNext || 'Next match');
        btnDetailNext.disabled = true;
        var detailMatchMeta = document.createElement('span');
        detailMatchMeta.className = 'timeline-sk-detail-search-meta';
        detailMatchMeta.setAttribute('aria-live', 'polite');
        detailSearchRow.appendChild(detailSearch);
        detailSearchRow.appendChild(btnDetailPrev);
        detailSearchRow.appendChild(btnDetailNext);
        detailSearchRow.appendChild(detailMatchMeta);
        var pre = document.createElement('pre');
        pre.className = 'timeline-sk-detail-pre';
        detail.appendChild(detailTitleEl);
        detail.appendChild(detailHintEl);
        detail.appendChild(detailSearchRow);
        detail.appendChild(pre);
        split.appendChild(listWrap);
        split.appendChild(detail);
        host.appendChild(split);

        var detailJsonRaw = '';
        var detailHits = [];
        var detailHitIndex = 0;

        function highlightJsonHtml(raw, q) {
            if (!q || !String(q).trim()) return escapeHtml(raw);
            var needle = String(q).trim();
            var lower = raw.toLowerCase();
            var nl = needle.toLowerCase();
            var out = '';
            var pos = 0;
            while (pos < raw.length) {
                var idx = lower.indexOf(nl, pos);
                if (idx < 0) {
                    out += escapeHtml(raw.slice(pos));
                    break;
                }
                out += escapeHtml(raw.slice(pos, idx));
                out += '<mark class="timeline-sk-json-hit">';
                out += escapeHtml(raw.slice(idx, idx + needle.length));
                out += '</mark>';
                pos = idx + needle.length;
            }
            return out;
        }

        function applyDetailJsonSearch() {
            detailMatchMeta.textContent = '';
            btnDetailPrev.disabled = true;
            btnDetailNext.disabled = true;
            detailHits = [];
            detailHitIndex = 0;
            if (!detailJsonRaw) {
                pre.textContent = '';
                return;
            }
            var q = detailSearch.value;
            if (!q || !q.trim()) {
                pre.textContent = detailJsonRaw;
                return;
            }
            pre.innerHTML = highlightJsonHtml(detailJsonRaw, q);
            detailHits = Array.prototype.slice.call(pre.querySelectorAll('mark.timeline-sk-json-hit'));
            var n = detailHits.length;
            if (n === 0) {
                pre.textContent = detailJsonRaw;
                detailMatchMeta.textContent = labels.detailSearchZero || '';
                return;
            }
            btnDetailPrev.disabled = false;
            btnDetailNext.disabled = false;
            detailHitIndex = 0;
            detailHits[0].classList.add('timeline-sk-json-hit-active');
            detailMatchMeta.textContent = (labels.detailSearchMatches || '{cur} / {total}')
                .replace('{cur}', '1')
                .replace('{total}', String(n));
            try {
                detailHits[0].scrollIntoView({ block: 'nearest', inline: 'nearest' });
            } catch (err) {
                /* ignore */
            }
        }

        function scrollDetailHit(delta) {
            if (!detailHits.length) return;
            detailHits[detailHitIndex].classList.remove('timeline-sk-json-hit-active');
            detailHitIndex = (detailHitIndex + delta + detailHits.length) % detailHits.length;
            var m = detailHits[detailHitIndex];
            m.classList.add('timeline-sk-json-hit-active');
            detailMatchMeta.textContent = (labels.detailSearchMatches || '{cur} / {total}')
                .replace('{cur}', String(detailHitIndex + 1))
                .replace('{total}', String(detailHits.length));
            try {
                m.scrollIntoView({ block: 'nearest', inline: 'nearest' });
            } catch (err) {
                /* ignore */
            }
        }

        function setDetailContent(evObj) {
            try {
                detailJsonRaw = JSON.stringify(evObj, null, 2);
            } catch (err) {
                detailJsonRaw = String(err);
            }
            applyDetailJsonSearch();
        }

        detailSearch.addEventListener('input', function () {
            applyDetailJsonSearch();
        });
        btnDetailPrev.addEventListener('click', function () {
            scrollDetailHit(-1);
        });
        btnDetailNext.addEventListener('click', function () {
            scrollDetailHit(1);
        });

        var zoomFooter = document.createElement('div');
        zoomFooter.className = 'timeline-sk-zoom-footer';
        var zoomTitle = document.createElement('div');
        zoomTitle.className = 'timeline-sk-zoom-title';
        zoomTitle.textContent = labels.zoomRangeTitle;
        zoomFooter.appendChild(zoomTitle);

        var brushTrack = document.createElement('div');
        brushTrack.className = 'timeline-sk-brush-track';
        brushTrack.setAttribute('role', 'slider');
        brushTrack.setAttribute('aria-label', labels.zoomBrushHelp);
        var brushDensity = document.createElement('canvas');
        brushDensity.className = 'timeline-sk-brush-density';
        brushDensity.setAttribute('aria-hidden', 'true');
        var brushShadeLeft = document.createElement('div');
        brushShadeLeft.className = 'timeline-sk-brush-shade timeline-sk-brush-shade-left';
        var brushShadeRight = document.createElement('div');
        brushShadeRight.className = 'timeline-sk-brush-shade timeline-sk-brush-shade-right';
        var brushWinEl = document.createElement('div');
        brushWinEl.className = 'timeline-sk-brush-window';
        brushTrack.appendChild(brushDensity);
        brushTrack.appendChild(brushShadeLeft);
        brushTrack.appendChild(brushShadeRight);
        brushTrack.appendChild(brushWinEl);
        zoomFooter.appendChild(brushTrack);
        var brushHelp = document.createElement('p');
        brushHelp.className = 'timeline-sk-brush-help';
        brushHelp.textContent = labels.zoomBrushHelp;
        zoomFooter.appendChild(brushHelp);

        var magRow = document.createElement('div');
        magRow.className = 'timeline-sk-zoom-mag-row';
        var magId = 'tsk-mag-' + Math.random().toString(36).slice(2, 11);
        var magLabel = document.createElement('label');
        magLabel.className = 'timeline-sk-slider-label timeline-sk-zoom-mag-label';
        magLabel.setAttribute('for', magId);
        magLabel.textContent = labels.zoomDetail;
        var zoomMag = document.createElement('input');
        zoomMag.type = 'range';
        zoomMag.className = 'timeline-sk-range timeline-sk-zoom-mag';
        zoomMag.id = magId;
        zoomMag.min = '0';
        zoomMag.max = '1000';
        zoomMag.value = '0';
        magRow.appendChild(magLabel);
        magRow.appendChild(zoomMag);
        zoomFooter.appendChild(magRow);

        var sliderRow = document.createElement('div');
        sliderRow.className = 'timeline-sk-slider-row';
        var labLo = document.createElement('label');
        labLo.className = 'timeline-sk-slider-label';
        labLo.textContent = labels.rangeStart;
        var rangeLo = document.createElement('input');
        rangeLo.type = 'range';
        rangeLo.className = 'timeline-sk-range';
        var labHi = document.createElement('label');
        labHi.className = 'timeline-sk-slider-label';
        labHi.textContent = labels.rangeEnd;
        var rangeHi = document.createElement('input');
        rangeHi.type = 'range';
        rangeHi.className = 'timeline-sk-range';
        sliderRow.appendChild(labLo);
        sliderRow.appendChild(rangeLo);
        sliderRow.appendChild(labHi);
        sliderRow.appendChild(rangeHi);
        zoomFooter.appendChild(sliderRow);
        host.appendChild(zoomFooter);

        var activeCat = '';
        var winLo = 0;
        var winHi = 0;
        var dragPx0 = 0;
        var dragPx1 = 0;
        var dragging = false;
        var panning = false;
        var lastPanClientX = 0;
        var pendingFullReset = true;
        var listHoverMs = null;
        /** Hovered category filter chip — highlight all matching events on band + brush. */
        var chipHoverCat = null;
        /** Time extent of `baseFiltered`; invalidated when filters change. */
        var lastExtent = { min: 0, max: 0 };
        var listRebuildTimer = null;
        var searchDebounceTimer = null;
        var vizPaintRaf = 0;
        var wheelAccumRaf = 0;

        /** Max vertical strokes on main band (histogram still uses all points in range). */
        var MAX_MAIN_STROKES = 2200;
        var MAX_BRUSH_CHIP_STROKES = 1000;
        var LIST_REBUILD_DEBOUNCE_MS = 70;
        var SEARCH_DEBOUNCE_MS = 90;

        function computeBaseFiltered() {
            var q = search.value.trim().toLowerCase();
            var out = [];
            for (var i = 0; i < enriched.length; i++) {
                var row = enriched[i];
                if (activeCat && row.cat !== activeCat) continue;
                if (q && row.msg.toLowerCase().indexOf(q) < 0) {
                    if (!row.jtxt || row.jtxt.indexOf(q) < 0) continue;
                }
                out.push(row);
            }
            return out;
        }

        function cancelListRebuildTimer() {
            if (listRebuildTimer) {
                clearTimeout(listRebuildTimer);
                listRebuildTimer = null;
            }
        }

        function scheduleListRebuild() {
            cancelListRebuildTimer();
            listRebuildTimer = setTimeout(function () {
                listRebuildTimer = null;
                rebuildListAndMeta();
            }, LIST_REBUILD_DEBOUNCE_MS);
        }

        function requestVizPaint() {
            if (vizPaintRaf) return;
            vizPaintRaf = requestAnimationFrame(function () {
                vizPaintRaf = 0;
                paintVizOnly();
            });
        }

        function extentOf(rows) {
            if (!rows.length) return { min: 0, max: 0 };
            var mn = rows[0].tms;
            var mx = rows[0].tms;
            for (var i = 1; i < rows.length; i++) {
                mn = Math.min(mn, rows[i].tms);
                mx = Math.max(mx, rows[i].tms);
            }
            if (mx <= mn) {
                var pad = 3600000;
                return { min: mn - pad, max: mx + pad };
            }
            return { min: mn, max: mx };
        }

        /** Smallest allowed visible window (ms): tight enough for sub-second detail on long bugreports. */
        function minZoomWindowMs(span) {
            if (!isFinite(span) || span <= 0) return 1;
            var rel = span * 1e-8;
            return Math.max(1, Math.min(rel, span * 0.45));
        }

        function syncSlidersFromWindow() {
            if (!baseFiltered.length) return;
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            rangeLo.min = String(ex.min);
            rangeLo.max = String(ex.max);
            rangeHi.min = String(ex.min);
            rangeHi.max = String(ex.max);
            rangeLo.step = String(Math.max(1, Math.floor(span / 2000)));
            rangeHi.step = rangeLo.step;
            winLo = clamp(winLo, ex.min, ex.max);
            winHi = clamp(winHi, ex.min, ex.max);
            if (winHi <= winLo) {
                winHi = Math.min(ex.max, winLo + Math.max(span * 0.02, minZoomWindowMs(span)));
            }
            rangeLo.value = String(Math.round(winLo));
            rangeHi.value = String(Math.round(winHi));
            syncZoomMagFromWindow();
        }

        function syncZoomMagFromWindow() {
            if (!zoomMag || !baseFiltered.length) return;
            var ex = lastExtent;
            var span = ex.max - ex.min;
            if (!isFinite(span) || span <= 0) return;
            var minW = Math.min(minZoomWindowMs(span), span * 0.99);
            var wv = Math.max(winHi - winLo, minW);
            if (wv >= span * 0.999) {
                zoomMag.value = '0';
                return;
            }
            var ratio = span / minW;
            if (ratio <= 1) {
                zoomMag.value = '1000';
                return;
            }
            var t = 1000 * (1 - Math.log(wv / minW) / Math.log(ratio));
            zoomMag.value = String(clamp(Math.round(t), 0, 1000));
        }

        function syncBrushVisual() {
            if (!brushWinEl || !brushTrack) return;
            if (!baseFiltered.length) {
                brushWinEl.style.left = '0%';
                brushWinEl.style.width = '0%';
                if (brushShadeLeft) brushShadeLeft.style.display = 'none';
                if (brushShadeRight) brushShadeRight.style.display = 'none';
                if (brushDensity) {
                    var c0 = brushDensity.getContext('2d');
                    if (c0) c0.clearRect(0, 0, brushDensity.width, brushDensity.height);
                }
                brushWinEl.classList.remove('timeline-sk-brush-window-zoomed');
                return;
            }
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            var lo = (winLo - ex.min) / span;
            var hi = (winHi - ex.min) / span;
            lo = clamp(lo, 0, 1);
            hi = clamp(hi, 0, 1);
            if (hi < lo) {
                var t = lo;
                lo = hi;
                hi = t;
            }
            var w = Math.max(hi - lo, 0.001);
            brushWinEl.style.left = lo * 100 + '%';
            brushWinEl.style.width = w * 100 + '%';

            var fullSpan = hi - lo >= 0.998;
            brushWinEl.classList.toggle('timeline-sk-brush-window-zoomed', !fullSpan);
            if (brushShadeLeft) {
                if (fullSpan || lo <= 0.001) {
                    brushShadeLeft.style.display = 'none';
                } else {
                    brushShadeLeft.style.display = 'block';
                    brushShadeLeft.style.left = '0';
                    brushShadeLeft.style.width = lo * 100 + '%';
                }
            }
            if (brushShadeRight) {
                if (fullSpan || hi >= 0.999) {
                    brushShadeRight.style.display = 'none';
                } else {
                    brushShadeRight.style.display = 'block';
                    brushShadeRight.style.left = hi * 100 + '%';
                    brushShadeRight.style.width = (1 - hi) * 100 + '%';
                }
            }
            resizeBrushMini();
        }

        var baseFiltered = [];

        function resetWindowToFull() {
            var ex = lastExtent;
            winLo = ex.min;
            winHi = ex.max;
            syncSlidersFromWindow();
        }

        function updateWindowChrome() {
            if (!baseFiltered.length) return;
            winSpan.textContent = labels.windowLabel + ': ' + humanDuration(winHi - winLo);
            if (winDatesRow) {
                winDatesRow.innerHTML =
                    '<div class="timeline-sk-window-date-line"><span class="timeline-sk-window-date-label">' +
                    escapeHtml(labels.windowFrom || 'Start') +
                    '</span> <span class="timeline-sk-window-date-value">' +
                    escapeHtml(fmtDateContext(winLo)) +
                    '</span></div><div class="timeline-sk-window-date-line"><span class="timeline-sk-window-date-label">' +
                    escapeHtml(labels.windowTo || 'End') +
                    '</span> <span class="timeline-sk-window-date-value">' +
                    escapeHtml(fmtDateContext(winHi)) +
                    '</span></div>';
            }
        }

        function paintVizOnly() {
            syncBrushVisual();
            drawCanvas();
        }

        function rebuildListAndMeta() {
            if (!baseFiltered.length) return;
            var visible = getVisibleInWindow();
            var cap = Math.min(visible.length, maxRender);
            listEl.textContent = '';
            for (var r = 0; r < cap; r++) {
                var item = visible[r];
                var approx = item.ev.time_is_approximate === true;
                var bind = item.ev.event_time_binding;
                var timeTag = '';
                if (bind === 'snapshot_only') timeTag = labels.bindingSnapshot;
                else if (bind === 'system_fallback') timeTag = labels.bindingSystemFallback;
                else if (approx) timeTag = labels.approx;
                var rowEl = document.createElement('button');
                rowEl.type = 'button';
                rowEl.className = 'timeline-sk-row';
                rowEl.dataset.tms = String(item.tms);
                rowEl.style.borderLeftColor = catCol(item.cat);
                rowEl.innerHTML =
                    '<span class="timeline-sk-row-time">' +
                    escapeHtml(fmtLocal(item.tms)) +
                    (timeTag
                        ? ' <span class="timeline-sk-approx">(' + escapeHtml(timeTag) + ')</span>'
                        : '') +
                    '</span><span class="timeline-sk-row-cat">' +
                    escapeHtml(item.cat) +
                    '</span><span class="timeline-sk-row-msg">' +
                    escapeHtml(item.msg.length > 220 ? item.msg.slice(0, 217) + '…' : item.msg) +
                    '</span>';
                (function (evObj, el, tms) {
                    el.addEventListener('click', function () {
                        listEl.querySelectorAll('.timeline-sk-row').forEach(function (x) {
                            x.classList.remove('timeline-sk-row-selected');
                        });
                        el.classList.add('timeline-sk-row-selected');
                        setDetailContent(evObj);
                    });
                    el.addEventListener('pointerenter', function () {
                        listHoverMs = tms;
                        requestVizPaint();
                    });
                    el.addEventListener('pointerleave', function () {
                        listHoverMs = null;
                        requestVizPaint();
                    });
                })(item.ev, rowEl, item.tms);
                listEl.appendChild(rowEl);
            }

            var msg = labels.showing
                .replace('{shown}', String(cap))
                .replace('{filtered}', String(visible.length))
                .replace('{total}', String(baseFiltered.length));
            if (visible.length > maxRender) {
                msg += ' ' + labels.capped.replace('{max}', String(maxRender));
            }
            meta.textContent = msg;
            updateWindowChrome();
            if (cap === 0 && visible.length === 0) {
                var empty2 = document.createElement('div');
                empty2.className = 'timeline-sk-empty';
                empty2.textContent = labels.noMatch;
                listEl.appendChild(empty2);
            }
        }

        function applyWindowChangeFast() {
            if (!baseFiltered.length) return;
            syncSlidersFromWindow();
            updateWindowChrome();
            paintVizOnly();
            scheduleListRebuild();
        }

        /** After zoom buttons, brush click, drag-zoom, or pan end — list must match window immediately. */
        function syncViewAfterDiscreteWindowChange() {
            cancelListRebuildTimer();
            if (!baseFiltered.length) return;
            syncSlidersFromWindow();
            updateWindowChrome();
            rebuildListAndMeta();
            paintVizOnly();
        }

        function resizeCanvas() {
            var w = canvasWrap.clientWidth || 600;
            var dpr = typeof window.devicePixelRatio === 'number' ? window.devicePixelRatio : 1;
            canvas.width = Math.floor(w * dpr);
            canvas.height = Math.floor(vizH * dpr);
            canvas.style.width = w + 'px';
            canvas.style.height = vizH + 'px';
            var ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            }
            drawCanvas();
        }

        function drawCanvas() {
            var ctx = canvas.getContext('2d');
            if (!ctx) return;
            var wCss = canvas.offsetWidth || canvas.clientWidth || 600;
            var hCss = vizH;
            var ex = lastExtent;
            var spanFull = ex.max - ex.min || 1;
            var winW = winHi - winLo;
            if (!isFinite(winW) || winW <= 0) {
                winW = spanFull;
            }
            var pad = Math.max(winW * 0.04, spanFull * 0.0003, 1);
            var vmin = clamp(winLo - pad, ex.min, ex.max);
            var vmax = clamp(winHi + pad, ex.min, ex.max);
            if (vmax <= vmin) {
                vmin = ex.min;
                vmax = ex.max;
            }
            var span = vmax - vmin || 1;

            var W = wCss;
            var H = hCss;
            ctx.clearRect(0, 0, W, H);
            var bg = isDark() ? '#1e1e24' : '#f0f2f7';
            ctx.fillStyle = bg;
            ctx.fillRect(0, 0, W, H);

            var bins = Math.min(800, Math.max(64, Math.floor(W / 1.2)));
            var hist = new Array(bins);
            for (var b = 0; b < bins; b++) hist[b] = 0;
            for (var i = 0; i < baseFiltered.length; i++) {
                var t = baseFiltered[i].tms;
                if (t < vmin || t > vmax) continue;
                var u = (t - vmin) / span;
                var bi = clamp(Math.floor(u * (bins - 0.0001)), 0, bins - 1);
                hist[bi]++;
            }
            var hmax = 1;
            for (var h = 0; h < bins; h++) hmax = Math.max(hmax, hist[h]);
            for (var x = 0; x < bins; x++) {
                var bh = (hist[x] / hmax) * (H - 18);
                var grad = flashy
                    ? isDark()
                        ? 'rgba(168,85,247,0.55)'
                        : 'rgba(236,72,153,0.55)'
                    : isDark()
                      ? 'rgba(66,165,245,0.35)'
                      : 'rgba(33,150,243,0.45)';
                ctx.fillStyle = grad;
                ctx.fillRect((x / bins) * W, H - bh - 4, Math.ceil(W / bins) + 0.5, bh + 4);
            }

            var xWinLo = ((winLo - vmin) / span) * W;
            var xWinHi = ((winHi - vmin) / span) * W;
            ctx.fillStyle = isDark() ? 'rgba(0,0,0,0.38)' : 'rgba(255,255,255,0.5)';
            ctx.fillRect(0, 0, clamp(xWinLo, 0, W), H);
            ctx.fillRect(clamp(xWinHi, 0, W), 0, W - clamp(xWinHi, 0, W), H);

            var strokeBuf = [];
            for (var k = 0; k < baseFiltered.length; k++) {
                var row = baseFiltered[k];
                if (row.tms < vmin || row.tms > vmax) continue;
                var xf = (row.tms - vmin) / span;
                var xi = xf * W;
                if (xi < -1 || xi > W + 1) continue;
                strokeBuf.push(row);
            }
            var stStep = strokeBuf.length > MAX_MAIN_STROKES ? Math.ceil(strokeBuf.length / MAX_MAIN_STROKES) : 1;
            for (var sk = 0; sk < strokeBuf.length; sk += stStep) {
                var srow = strokeBuf[sk];
                var xf2 = (srow.tms - vmin) / span;
                var xi2 = xf2 * W;
                var inside = srow.tms >= winLo && srow.tms <= winHi;
                ctx.globalAlpha = inside ? 0.95 : 0.22;
                ctx.strokeStyle = catCol(srow.cat);
                ctx.lineWidth = inside ? (flashy ? 2.1 : 1.35) : flashy ? 1.15 : 0.8;
                ctx.beginPath();
                ctx.moveTo(xi2, 4);
                ctx.lineTo(xi2, H - 6);
                ctx.stroke();
            }
            ctx.globalAlpha = 1;

            if (chipHoverCat) {
                ctx.save();
                ctx.strokeStyle = isDark() ? 'rgba(45, 212, 191, 0.92)' : 'rgba(13, 148, 136, 0.92)';
                ctx.lineWidth = 2.75;
                ctx.shadowColor = isDark() ? 'rgba(45, 212, 191, 0.35)' : 'rgba(13, 148, 136, 0.3)';
                ctx.shadowBlur = 5;
                var chipBuf = [];
                for (var hc = 0; hc < baseFiltered.length; hc++) {
                    var hrow = baseFiltered[hc];
                    if (hrow.cat !== chipHoverCat) continue;
                    if (hrow.tms < vmin || hrow.tms > vmax) continue;
                    var hxi = ((hrow.tms - vmin) / span) * W;
                    if (hxi < -1 || hxi > W + 1) continue;
                    chipBuf.push(hxi);
                }
                var chStep = chipBuf.length > MAX_MAIN_STROKES ? Math.ceil(chipBuf.length / MAX_MAIN_STROKES) : 1;
                for (var ci = 0; ci < chipBuf.length; ci += chStep) {
                    var hx = chipBuf[ci];
                    ctx.globalAlpha = 0.88;
                    ctx.beginPath();
                    ctx.moveTo(hx, 3);
                    ctx.lineTo(hx, H - 5);
                    ctx.stroke();
                }
                ctx.restore();
                ctx.globalAlpha = 1;
            }

            if (listHoverMs != null && isFinite(listHoverMs)) {
                var xh = ((listHoverMs - vmin) / span) * W;
                var clipped = xh < 0 || xh > W;
                xh = clamp(xh, 3, W - 3);
                ctx.save();
                ctx.setLineDash(clipped ? [5, 4] : []);
                ctx.strokeStyle = isDark() ? 'rgba(251, 191, 36, 0.98)' : 'rgba(180, 83, 9, 0.98)';
                ctx.lineWidth = clipped ? 2.5 : 3;
                ctx.shadowColor = isDark() ? 'rgba(251, 191, 36, 0.45)' : 'rgba(217, 119, 6, 0.35)';
                ctx.shadowBlur = clipped ? 4 : 8;
                ctx.beginPath();
                ctx.moveTo(xh, 2);
                ctx.lineTo(xh, H - 2);
                ctx.stroke();
                ctx.restore();
            }

            ctx.strokeStyle = isDark() ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.08)';
            ctx.strokeRect(0.5, 0.5, W - 1, H - 1);
        }

        /** Full-range event density on the brush strip; window + shades updated in syncBrushVisual. */
        function resizeBrushMini() {
            if (!brushDensity || !brushTrack) return;
            var w = brushTrack.clientWidth || 200;
            var h = brushTrack.clientHeight || 26;
            if (w < 2 || h < 2) return;
            var dpr = typeof window.devicePixelRatio === 'number' ? window.devicePixelRatio : 1;
            var nw = Math.floor(w * dpr);
            var nh = Math.floor(h * dpr);
            if (brushDensity.width !== nw || brushDensity.height !== nh) {
                brushDensity.width = nw;
                brushDensity.height = nh;
                brushDensity.style.width = w + 'px';
                brushDensity.style.height = h + 'px';
                var ctxR = brushDensity.getContext('2d');
                if (ctxR) ctxR.setTransform(dpr, 0, 0, dpr, 0, 0);
            }
            drawBrushMini();
        }

        function drawBrushMini() {
            if (!brushDensity || !brushTrack) return;
            var ctx = brushDensity.getContext('2d');
            if (!ctx) return;
            var W = brushTrack.clientWidth || brushDensity.offsetWidth || 200;
            var H = brushTrack.clientHeight || 26;
            if (W < 2 || H < 2) return;
            ctx.clearRect(0, 0, W, H);
            if (!baseFiltered.length) return;

            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            var bins = Math.min(200, Math.max(24, Math.floor(W / 2)));
            var hist = new Array(bins);
            for (var b = 0; b < bins; b++) hist[b] = 0;
            for (var i = 0; i < baseFiltered.length; i++) {
                var t = baseFiltered[i].tms;
                var u = (t - ex.min) / span;
                var bi = clamp(Math.floor(u * (bins - 0.0001)), 0, bins - 1);
                hist[bi]++;
            }
            var hmax = 1;
            for (var h = 0; h < bins; h++) hmax = Math.max(hmax, hist[h]);
            var bg = isDark() ? '#25252d' : '#e8ebf2';
            ctx.fillStyle = bg;
            ctx.fillRect(0, 0, W, H);
            var padTop = 3;
            var padBot = 3;
            var innerH = H - padTop - padBot;
            for (var x = 0; x < bins; x++) {
                var bh = (hist[x] / hmax) * innerH;
                var grad = flashy
                    ? isDark()
                        ? 'rgba(192,132,252,0.75)'
                        : 'rgba(219,39,119,0.72)'
                    : isDark()
                      ? 'rgba(100,181,246,0.7)'
                      : 'rgba(25,118,210,0.65)';
                ctx.fillStyle = grad;
                ctx.fillRect((x / bins) * W, H - padBot - bh, Math.ceil(W / bins) + 0.5, bh + 0.5);
            }
            ctx.strokeStyle = isDark() ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
            ctx.strokeRect(0.5, 0.5, W - 1, H - 1);

            if (chipHoverCat) {
                ctx.save();
                ctx.strokeStyle = isDark() ? 'rgba(45, 212, 191, 0.9)' : 'rgba(13, 148, 136, 0.9)';
                ctx.lineWidth = 1.5;
                ctx.globalAlpha = 0.85;
                var miniChip = [];
                for (var bi = 0; bi < baseFiltered.length; bi++) {
                    var brow = baseFiltered[bi];
                    if (brow.cat !== chipHoverCat) continue;
                    var bx = ((brow.tms - ex.min) / span) * W;
                    bx = clamp(bx, 1, W - 1);
                    miniChip.push(bx);
                }
                var mStep =
                    miniChip.length > MAX_BRUSH_CHIP_STROKES
                        ? Math.ceil(miniChip.length / MAX_BRUSH_CHIP_STROKES)
                        : 1;
                for (var mi = 0; mi < miniChip.length; mi += mStep) {
                    var mx = miniChip[mi];
                    ctx.beginPath();
                    ctx.moveTo(mx, 0);
                    ctx.lineTo(mx, H);
                    ctx.stroke();
                }
                ctx.restore();
            }

            if (listHoverMs != null && isFinite(listHoverMs)) {
                var xh = ((listHoverMs - ex.min) / span) * W;
                xh = clamp(xh, 2, W - 2);
                ctx.strokeStyle = isDark() ? '#fbbf24' : '#b45309';
                ctx.lineWidth = 2.5;
                ctx.shadowColor = isDark() ? 'rgba(251, 191, 36, 0.5)' : 'rgba(180, 83, 9, 0.45)';
                ctx.shadowBlur = 5;
                ctx.beginPath();
                ctx.moveTo(xh, 1);
                ctx.lineTo(xh, H - 1);
                ctx.stroke();
                ctx.shadowBlur = 0;
            }
        }

        function getVisibleInWindow() {
            var out = [];
            for (var i = 0; i < baseFiltered.length; i++) {
                var row = baseFiltered[i];
                if (row.tms >= winLo && row.tms <= winHi) out.push(row);
            }
            return out;
        }

        function renderList() {
            listHoverMs = null;
            cancelListRebuildTimer();
            baseFiltered = computeBaseFiltered();
            lastExtent = extentOf(baseFiltered);
            var ex = lastExtent;
            if (!baseFiltered.length) {
                winLo = 0;
                winHi = 0;
                meta.textContent = labels.noMatch;
                listEl.textContent = '';
                var empty = document.createElement('div');
                empty.className = 'timeline-sk-empty';
                empty.textContent = labels.noMatch;
                listEl.appendChild(empty);
                winSpan.textContent = '';
                if (winDatesRow) winDatesRow.innerHTML = '';
                if (zoomFooter) {
                    zoomFooter.style.opacity = '0.48';
                    zoomFooter.style.pointerEvents = 'none';
                }
                if (zoomMag) zoomMag.disabled = true;
                rangeLo.disabled = true;
                rangeHi.disabled = true;
                paintVizOnly();
                return;
            }
            if (zoomFooter) {
                zoomFooter.style.opacity = '1';
                zoomFooter.style.pointerEvents = 'auto';
            }
            if (zoomMag) zoomMag.disabled = false;
            rangeLo.disabled = false;
            rangeHi.disabled = false;
            var overlap = winHi > winLo && winLo <= ex.max && winHi >= ex.min;
            if (pendingFullReset || !overlap) {
                pendingFullReset = false;
                resetWindowToFull();
            } else {
                winLo = clamp(winLo, ex.min, ex.max);
                winHi = clamp(winHi, ex.min, ex.max);
                if (winHi <= winLo) resetWindowToFull();
                else syncSlidersFromWindow();
            }

            rebuildListAndMeta();
            paintVizOnly();
        }

        function applyChips(active) {
            activeCat = active;
            var chips = chipRow.querySelectorAll('.timeline-sk-chip');
            for (var i = 0; i < chips.length; i++) {
                var on = chips[i].dataset.cat === active;
                chips[i].classList.toggle('timeline-sk-chip-active', on);
            }
            pendingFullReset = true;
            renderList();
        }

        chipRow.addEventListener('click', function (e) {
            var btn = e.target.closest('.timeline-sk-chip');
            if (!btn) return;
            applyChips(btn.dataset.cat || '');
        });

        search.addEventListener('input', function () {
            pendingFullReset = true;
            if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(function () {
                searchDebounceTimer = null;
                renderList();
            }, SEARCH_DEBOUNCE_MS);
        });

        btnFit.addEventListener('click', function () {
            pendingFullReset = true;
            renderList();
        });

        function zoomWindow(ratio) {
            if (!baseFiltered.length) return;
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            var cur = winHi - winLo;
            var center = (winLo + winHi) / 2;
            var newW = clamp(cur * ratio, minZoomWindowMs(span), span);
            winLo = center - newW / 2;
            winHi = center + newW / 2;
            if (winLo < ex.min) {
                winHi += ex.min - winLo;
                winLo = ex.min;
            }
            if (winHi > ex.max) {
                winLo -= winHi - ex.max;
                winHi = ex.max;
            }
            syncViewAfterDiscreteWindowChange();
        }
        btnZoomIn.addEventListener('click', function () {
            zoomWindow(0.58);
        });
        btnZoomOut.addEventListener('click', function () {
            zoomWindow(1.72);
        });

        function onRangeChange() {
            var lo = parseFloat(rangeLo.value);
            var hi = parseFloat(rangeHi.value);
            if (isNaN(lo) || isNaN(hi)) return;
            if (lo > hi) {
                var t = lo;
                lo = hi;
                hi = t;
            }
            var ex = lastExtent;
            var minSpan = minZoomWindowMs(ex.max - ex.min || 1);
            if (hi - lo < minSpan) {
                hi = lo + minSpan;
                if (hi > ex.max) {
                    hi = ex.max;
                    lo = hi - minSpan;
                }
            }
            winLo = lo;
            winHi = hi;
            applyWindowChangeFast();
        }
        rangeLo.addEventListener('input', onRangeChange);
        rangeHi.addEventListener('input', onRangeChange);

        zoomMag.addEventListener('input', function () {
            if (!baseFiltered.length) return;
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            var minW = Math.min(minZoomWindowMs(span), span * 0.99);
            var t = parseFloat(zoomMag.value);
            if (isNaN(t)) return;
            var c = (winLo + winHi) / 2;
            if (t <= 0) {
                winLo = ex.min;
                winHi = ex.max;
            } else if (t >= 1000) {
                var wMin = minW;
                winLo = c - wMin / 2;
                winHi = c + wMin / 2;
            } else {
                var ratio = span / minW;
                var w = minW * Math.pow(ratio, 1 - t / 1000);
                winLo = c - w / 2;
                winHi = c + w / 2;
            }
            if (winLo < ex.min) {
                winHi += ex.min - winLo;
                winLo = ex.min;
            }
            if (winHi > ex.max) {
                winLo -= winHi - ex.max;
                winHi = ex.max;
            }
            applyWindowChangeFast();
        });

        brushTrack.addEventListener('click', function (e) {
            if (!baseFiltered.length) return;
            var rect = brushTrack.getBoundingClientRect();
            if (rect.width <= 0) return;
            var frac = clamp((e.clientX - rect.left) / rect.width, 0, 1);
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            var w = winHi - winLo;
            if (w <= 0 || !isFinite(w)) {
                w = span * 0.15;
            }
            var center = ex.min + frac * span;
            winLo = center - w / 2;
            winHi = center + w / 2;
            if (winLo < ex.min) {
                winHi += ex.min - winLo;
                winLo = ex.min;
            }
            if (winHi > ex.max) {
                winLo -= winHi - ex.max;
                winHi = ex.max;
            }
            syncViewAfterDiscreteWindowChange();
        });

        canvasWrap.addEventListener('mousedown', function (e) {
            if (e.button !== 0) return;
            var rect = canvasWrap.getBoundingClientRect();
            if (e.shiftKey || e.altKey) {
                panning = true;
                dragging = false;
                selectionEl.style.display = 'none';
                lastPanClientX = e.clientX;
                return;
            }
            panning = false;
            dragging = true;
            dragPx0 = e.clientX - rect.left;
            dragPx1 = dragPx0;
            selectionEl.style.display = 'block';
            selectionEl.style.left = dragPx0 + 'px';
            selectionEl.style.width = '0px';
        });

        document.addEventListener('mousemove', function (e) {
            var rect = canvasWrap.getBoundingClientRect();
            var W = rect.width;
            if (panning && W > 0) {
                var dPx = e.clientX - lastPanClientX;
                lastPanClientX = e.clientX;
                var ex = lastExtent;
                var viewSpan = winHi - winLo || 1;
                var dMs = (-dPx / W) * viewSpan;
                winLo += dMs;
                winHi += dMs;
                if (winLo < ex.min) {
                    winHi += ex.min - winLo;
                    winLo = ex.min;
                }
                if (winHi > ex.max) {
                    winLo -= winHi - ex.max;
                    winHi = ex.max;
                }
                applyWindowChangeFast();
                return;
            }
            if (!dragging) return;
            dragPx1 = clamp(e.clientX - rect.left, 0, rect.width);
            var left = Math.min(dragPx0, dragPx1);
            var width = Math.abs(dragPx1 - dragPx0);
            selectionEl.style.left = left + 'px';
            selectionEl.style.width = width + 'px';
        });

        document.addEventListener('mouseup', function () {
            if (panning) {
                panning = false;
                syncViewAfterDiscreteWindowChange();
                return;
            }
            if (!dragging) return;
            dragging = false;
            selectionEl.style.display = 'none';
            var rect = canvasWrap.getBoundingClientRect();
            var W = rect.width;
            if (W <= 0) return;
            var dist = Math.abs(dragPx1 - dragPx0);
            var ex = lastExtent;
            var span = ex.max - ex.min || 1;
            if (dist < 4) {
                var frac = dragPx0 / W;
                var center = ex.min + frac * span;
                var curW = winHi - winLo;
                var nw = Math.max(minZoomWindowMs(span), curW * 0.85);
                winLo = center - nw / 2;
                winHi = center + nw / 2;
                if (winLo < ex.min) {
                    winHi += ex.min - winLo;
                    winLo = ex.min;
                }
                if (winHi > ex.max) {
                    winLo -= winHi - ex.max;
                    winHi = ex.max;
                }
                syncViewAfterDiscreteWindowChange();
                return;
            }
            var left = Math.min(dragPx0, dragPx1);
            var right = Math.max(dragPx0, dragPx1);
            winLo = ex.min + (left / W) * span;
            winHi = ex.min + (right / W) * span;
            var minDrag = minZoomWindowMs(span);
            if (winHi - winLo < minDrag) {
                winHi = winLo + minDrag;
            }
            syncViewAfterDiscreteWindowChange();
        });

        canvasWrap.addEventListener(
            'wheel',
            function (e) {
                if (!baseFiltered.length) return;
                e.preventDefault();
                var rect = canvasWrap.getBoundingClientRect();
                var W = rect.width;
                var mx = clamp(e.clientX - rect.left, 0, W);
                var dy = e.deltaY;
                if (wheelAccumRaf) cancelAnimationFrame(wheelAccumRaf);
                wheelAccumRaf = requestAnimationFrame(function () {
                    wheelAccumRaf = 0;
                    var ex = lastExtent;
                    var span = ex.max - ex.min || 1;
                    var frac = W > 0 ? mx / W : 0.5;
                    var center = winLo + frac * (winHi - winLo);
                    var curSpan = winHi - winLo;
                    var factor = dy > 0 ? 1.18 : 1 / 1.18;
                    var newSpan = clamp(curSpan * factor, minZoomWindowMs(span), span);
                    winLo = center - frac * newSpan;
                    winHi = winLo + newSpan;
                    if (winLo < ex.min) {
                        winHi += ex.min - winLo;
                        winLo = ex.min;
                    }
                    if (winHi > ex.max) {
                        winLo -= winHi - ex.max;
                        winHi = ex.max;
                    }
                    applyWindowChangeFast();
                });
            },
            { passive: false }
        );

        canvasWrap.addEventListener('dblclick', function (e) {
            e.preventDefault();
            pendingFullReset = true;
            renderList();
        });

        if (typeof ResizeObserver !== 'undefined') {
            var ro = new ResizeObserver(function () {
                resizeCanvas();
            });
            ro.observe(canvasWrap);
            var roBrush = new ResizeObserver(function () {
                resizeBrushMini();
            });
            roBrush.observe(brushTrack);
        } else {
            window.addEventListener('resize', function () {
                resizeCanvas();
                resizeBrushMini();
            });
        }

        applyChips('');
        setTimeout(function () {
            resizeCanvas();
            resizeBrushMini();
        }, 0);
    }

    global.TimelineSketchView = { mount: mount, eventTimeMs: eventTimeMs, defaultCategory: defaultCategory };
})(typeof window !== 'undefined' ? window : this);

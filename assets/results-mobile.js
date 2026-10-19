/* Stamp column names onto result-table cells so narrow screens can stack each row. */
(function () {
    function stamp(table) {
        var ths = table.querySelectorAll('thead th');
        if (!ths.length) return;
        var headers = [];
        for (var i = 0; i < ths.length; i++) {
            headers.push((ths[i].textContent || '').replace(/\s+/g, ' ').trim());
        }
        var bodies = table.tBodies;
        for (var b = 0; b < bodies.length; b++) {
            var rows = bodies[b].rows;
            for (var r = 0; r < rows.length; r++) {
                var cells = rows[r].cells;
                for (var c = 0; c < cells.length; c++) {
                    if (cells[c].tagName !== 'TD') continue;
                    var label = headers[c] || '';
                    if (cells[c].getAttribute('data-label') !== label) {
                        cells[c].setAttribute('data-label', label);
                    }
                }
            }
        }
    }

    function stampAll(root) {
        var tables = root.querySelectorAll('table.data-table, table.iphone-dash-table');
        for (var i = 0; i < tables.length; i++) stamp(tables[i]);
    }

    function boot() {
        var root = document.getElementById('results');
        if (!root) return;
        var pending = false;
        var obs = new MutationObserver(function () {
            if (pending) return;
            pending = true;
            window.requestAnimationFrame(function () {
                pending = false;
                stampAll(root);
            });
        });
        obs.observe(root, { childList: true, subtree: true });
        stampAll(root);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();

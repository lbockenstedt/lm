// =============================================================================
// help.js - in-app documentation drawer (single source of truth).
//
// Clicking a help affordance (the header "Help" button, or an inline (i) icon
// produced by helpIcon()) slides a panel in from the FAR RIGHT and renders the
// matching canonical doc. The content comes straight from lm/docs/*.md via the
// hub's /docs and /docs/{name} endpoints - the SAME hand-authored docs used
// everywhere else. There is no second, WebUI-only doc set: reformat the
// canonical markdown and the drawer reflects it.
//
// Self-contained: on load it injects its own styles + drawer DOM and exposes
//   window.openHelp(name, section)   open a doc (optionally scroll to a ## section)
//   window.closeHelp()
//   window.helpForCurrentView()      open the doc mapped to the active view
//   window.helpIcon(name, section, label)  -> HTML string for an inline (i) button
//   window.LM_DOC_REGISTRY           view/module id -> doc name (editable map)
// =============================================================================
(function () {
    'use strict';

    // Map a WebUI view / module id -> canonical doc filename (without .md).
    // Keys are matched case-insensitively against the active view and common
    // module aliases; unknown views fall back to the doc index.
    const REGISTRY = {
        dashboard: 'architecture-topology',
        setup: 'lm-hub',
        settings: 'lm-hub',
        system: 'lm-hub',
        logs: 'logging-observability-contract',
        // modules
        ldap: 'ldap',
        firewall: 'opnsense',
        opnsense: 'opnsense',
        netbox: 'netbox',
        ipam: 'netbox',
        pxmx: 'pxmx',
        proxmox: 'pxmx',
        hypervisor: 'pxmx',
        cs: 'cs',
        simulation: 'cs',
        simulations: 'cs',
        dns: 'dns',
        dhcp: 'dhcp',
        nw: 'nw',
        network: 'nw',
        cppm: 'cppm',
        nac: 'cppm',
        le: 'le',
        certificates: 'le',
        webui: 'webui',
        bugfixer: 'bugfixer',
        agent: 'generic-agent',
        'generic-agent': 'generic-agent',
    };
    window.LM_DOC_REGISTRY = REGISTRY;

    // -- tiny markdown renderer -----------------------------------------------
    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function slug(s) {
        return String(s).toLowerCase().trim().replace(/[^\w]+/g, '-').replace(/^-+|-+$/g, '');
    }

    // Inline spans. Tokenize on backtick code spans first and ONLY transform the
    // non-code segments (so ** or digits inside `code` are never touched, and
    // restoring code can't collide with real numbers in prose like "caps at 200").
    function inline(text) {
        const parts = String(text).split(/(`[^`]+`)/);
        return parts.map(function (seg) {
            if (seg.length > 1 && seg.charAt(0) === '`' && seg.charAt(seg.length - 1) === '`') {
                return '<code>' + esc(seg.slice(1, -1)) + '</code>';
            }
            let s = esc(seg);
            // links [label](href)
            s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (_, label, href) {
                href = href.trim();
                // A link to another canonical doc (foo.md or foo.md#section) opens
                // it in the drawer instead of navigating the browser.
                const m = href.match(/^([a-z0-9-]+)\.md(?:#(.+))?$/i);
                if (m) {
                    const sec = m[2] ? ("'" + m[2].replace(/'/g, "\\'") + "'") : 'null';
                    return '<a href="#" onclick="openHelp(\'' + m[1] + '\',' + sec + ');return false;">' + label + '</a>';
                }
                if (/^https?:\/\//i.test(href)) {
                    return '<a href="' + href + '" target="_blank" rel="noopener">' + label + '</a>';
                }
                return '<a href="#" onclick="return false;">' + label + '</a>';
            });
            s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            s = s.replace(/(^|[^*])\*([^*\s][^*]*?)\*/g, '$1<em>$2</em>');
            return s;
        }).join('');
    }

    function renderMarkdown(md) {
        const lines = String(md).replace(/\r\n/g, '\n').split('\n');
        let html = '';
        let i = 0;
        let listType = null; // 'ul' | 'ol'

        function closeList() { if (listType) { html += '</' + listType + '>'; listType = null; } }

        while (i < lines.length) {
            let line = lines[i];

            // fenced code block
            const fence = line.match(/^```(.*)$/);
            if (fence) {
                closeList();
                i++;
                let buf = [];
                while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++; }
                i++; // consume closing fence
                html += '<pre><code>' + esc(buf.join('\n')) + '</code></pre>';
                continue;
            }

            // table: a header row followed by a |---|---| separator
            if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
                closeList();
                const parseRow = function (r) {
                    return r.trim().replace(/^\||\|$/g, '').split('|').map(function (c) { return c.trim(); });
                };
                const heads = parseRow(line);
                i += 2;
                let t = '<table><thead><tr>';
                heads.forEach(function (h) { t += '<th>' + inline(h) + '</th>'; });
                t += '</tr></thead><tbody>';
                while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
                    const cells = parseRow(lines[i]);
                    t += '<tr>' + cells.map(function (c) { return '<td>' + inline(c) + '</td>'; }).join('') + '</tr>';
                    i++;
                }
                t += '</tbody></table>';
                html += t;
                continue;
            }

            // headings
            const h = line.match(/^(#{1,6})\s+(.*)$/);
            if (h) {
                closeList();
                const lvl = h[1].length;
                html += '<h' + lvl + ' id="sec-' + slug(h[2]) + '">' + inline(h[2]) + '</h' + lvl + '>';
                i++;
                continue;
            }

            // horizontal rule
            if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
                closeList();
                html += '<hr>';
                i++;
                continue;
            }

            // unordered list
            let ul = line.match(/^\s*[-*]\s+(.*)$/);
            if (ul) {
                if (listType !== 'ul') { closeList(); html += '<ul>'; listType = 'ul'; }
                html += '<li>' + inline(ul[1]) + '</li>';
                i++;
                continue;
            }
            // ordered list
            let ol = line.match(/^\s*\d+\.\s+(.*)$/);
            if (ol) {
                if (listType !== 'ol') { closeList(); html += '<ol>'; listType = 'ol'; }
                html += '<li>' + inline(ol[1]) + '</li>';
                i++;
                continue;
            }

            // blank line
            if (/^\s*$/.test(line)) { closeList(); i++; continue; }

            // paragraph (gather consecutive non-blank, non-special lines)
            closeList();
            let para = [line];
            i++;
            while (i < lines.length && !/^\s*$/.test(lines[i]) &&
                   !/^(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s|\s*\|)/.test(lines[i]) &&
                   !/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(lines[i])) {
                para.push(lines[i]); i++;
            }
            html += '<p>' + inline(para.join(' ')) + '</p>';
        }
        closeList();
        return html;
    }

    // -- drawer DOM + styles --------------------------------------------------
    function ensureDom() {
        if (document.getElementById('lm-help-drawer')) return;

        const style = document.createElement('style');
        style.textContent = [
            '#lm-help-backdrop{position:fixed;inset:0;background:rgba(15,23,42,.35);',
            '  opacity:0;pointer-events:none;transition:opacity .2s ease;z-index:9998;}',
            '#lm-help-backdrop.open{opacity:1;pointer-events:auto;}',
            '#lm-help-drawer{position:fixed;top:0;right:0;height:100vh;width:min(30rem,92vw);',
            '  background:#fff;box-shadow:-8px 0 28px rgba(0,0,0,.18);z-index:9999;',
            '  display:flex;flex-direction:column;transform:translateX(100%);',
            '  transition:transform .22s cubic-bezier(.4,0,.2,1);}',
            '#lm-help-drawer.open{transform:translateX(0);}',
            '#lm-help-head{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;',
            '  background:#263040;color:#fff;flex-shrink:0;}',
            '#lm-help-head .lm-help-eyebrow{font-size:.6rem;letter-spacing:.12em;',
            '  text-transform:uppercase;color:#01A982;font-weight:700;}',
            '#lm-help-title{font-size:1.05rem;font-weight:700;line-height:1.2;}',
            '#lm-help-close{margin-left:auto;background:none;border:none;color:#cbd5e1;',
            '  font-size:1.4rem;line-height:1;cursor:pointer;padding:.1rem .35rem;border-radius:.35rem;}',
            '#lm-help-close:hover{color:#fff;background:rgba(255,255,255,.1);}',
            '#lm-help-body{overflow-y:auto;padding:1.25rem 1.5rem 3rem;color:#334155;',
            '  font-size:.875rem;line-height:1.6;}',
            '.lm-doc h1{font-size:1.25rem;font-weight:700;color:#0f172a;margin:.2rem 0 .75rem;}',
            '.lm-doc h2{font-size:1.02rem;font-weight:700;color:#0f172a;margin:1.5rem 0 .5rem;',
            '  padding-top:.75rem;border-top:1px solid #e2e8f0;}',
            '.lm-doc h3{font-size:.92rem;font-weight:700;color:#1e293b;margin:1rem 0 .35rem;}',
            '.lm-doc p{margin:.5rem 0;}',
            '.lm-doc ul,.lm-doc ol{margin:.5rem 0 .5rem 1.25rem;}',
            '.lm-doc li{margin:.2rem 0;}',
            '.lm-doc a{color:#01A982;text-decoration:none;font-weight:500;}',
            '.lm-doc a:hover{text-decoration:underline;}',
            '.lm-doc code{background:#f1f5f9;color:#0f766e;padding:.05rem .3rem;border-radius:.25rem;',
            '  font-size:.8em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}',
            '.lm-doc pre{background:#0f172a;color:#e2e8f0;padding:.85rem 1rem;border-radius:.5rem;',
            '  overflow-x:auto;margin:.75rem 0;}',
            '.lm-doc pre code{background:none;color:inherit;padding:0;font-size:.8rem;}',
            '.lm-doc table{border-collapse:collapse;width:100%;margin:.75rem 0;font-size:.8rem;',
            '  display:block;overflow-x:auto;}',
            '.lm-doc th,.lm-doc td{border:1px solid #e2e8f0;padding:.35rem .6rem;text-align:left;vertical-align:top;}',
            '.lm-doc th{background:#f8fafc;font-weight:700;}',
            '.lm-doc hr{border:none;border-top:1px solid #e2e8f0;margin:1.25rem 0;}',
            '.lm-doc-index{list-style:none;margin:0;padding:0;}',
            '.lm-doc-index li{margin:0;}',
            '.lm-doc-index a{display:block;padding:.5rem .25rem;border-bottom:1px solid #f1f5f9;}',
            '.lm-help-icon{display:inline-flex;align-items:center;justify-content:center;',
            '  width:1.05rem;height:1.05rem;border-radius:9999px;border:1px solid #cbd5e1;',
            '  color:#64748b;background:#fff;font-size:.7rem;font-weight:700;line-height:1;',
            '  cursor:pointer;vertical-align:middle;transition:all .12s ease;font-style:normal;}',
            '.lm-help-icon:hover{border-color:#01A982;color:#01A982;background:#f0fdf9;}'
        ].join('\n');
        document.head.appendChild(style);

        const backdrop = document.createElement('div');
        backdrop.id = 'lm-help-backdrop';
        backdrop.addEventListener('click', closeHelp);

        const drawer = document.createElement('div');
        drawer.id = 'lm-help-drawer';
        drawer.setAttribute('role', 'complementary');
        drawer.setAttribute('aria-label', 'Documentation');
        drawer.innerHTML =
            '<div id="lm-help-head">' +
                '<div>' +
                    '<div class="lm-help-eyebrow">Documentation</div>' +
                    '<div id="lm-help-title">Help</div>' +
                '</div>' +
                '<button id="lm-help-close" aria-label="Close help" title="Close">&times;</button>' +
            '</div>' +
            '<div id="lm-help-body"><div class="lm-doc"></div></div>';

        document.body.appendChild(backdrop);
        document.body.appendChild(drawer);
        drawer.querySelector('#lm-help-close').addEventListener('click', closeHelp);
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && drawer.classList.contains('open')) closeHelp();
        });
    }

    function paint(title, bodyHtml, sectionSlug) {
        ensureDom();
        document.getElementById('lm-help-title').textContent = title || 'Help';
        const body = document.querySelector('#lm-help-body .lm-doc');
        body.innerHTML = bodyHtml;
        const scroller = document.getElementById('lm-help-body');
        scroller.scrollTop = 0;
        if (sectionSlug) {
            const target = body.querySelector('#sec-' + sectionSlug);
            if (target) scroller.scrollTop = target.offsetTop - 8;
        }
    }

    function openDrawer() {
        ensureDom();
        document.getElementById('lm-help-backdrop').classList.add('open');
        document.getElementById('lm-help-drawer').classList.add('open');
    }

    function closeHelp() {
        const d = document.getElementById('lm-help-drawer');
        const b = document.getElementById('lm-help-backdrop');
        if (d) d.classList.remove('open');
        if (b) b.classList.remove('open');
    }

    // Open a doc by canonical name (without .md); optionally scroll to a ## title.
    async function openHelp(name, section) {
        ensureDom();
        openDrawer();
        if (!name) { return showIndex(); }
        const sectionSlug = section ? slug(section) : null;
        paint('Loading...', '<p style="color:#94a3b8">Loading documentation...</p>', null);
        try {
            const res = await fetch('/docs/' + encodeURIComponent(name));
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const data = await res.json();
            paint(data.title || name, renderMarkdown(data.markdown || ''), sectionSlug);
        } catch (err) {
            paint('Not found',
                '<p style="color:#e53e3e">Could not load <code>' + esc(name) + '</code>: ' + esc(err.message) +
                '</p><p><a href="#" onclick="openHelp();return false;">Browse all documentation &rarr;</a></p>', null);
        }
    }

    // The doc index - a browsable table of contents of every canonical doc.
    async function showIndex() {
        ensureDom();
        openDrawer();
        paint('Documentation', '<p style="color:#94a3b8">Loading...</p>', null);
        try {
            const res = await fetch('/docs');
            const data = await res.json();
            const items = (data.docs || []).map(function (d) {
                return '<li><a href="#" onclick="openHelp(\'' + d.name + '\');return false;">' +
                    esc(d.title || d.name) + '</a></li>';
            }).join('');
            paint('Documentation',
                '<p>Single source of truth - the canonical <code>lm/docs</code> set. ' +
                'Pick a topic:</p><ul class="lm-doc-index">' + items + '</ul>', null);
        } catch (err) {
            paint('Documentation', '<p style="color:#e53e3e">Could not load the doc index.</p>', null);
        }
    }

    // Resolve the active view/module to a doc and open it.
    function helpForCurrentView() {
        let key = (typeof window.currentView === 'string' && window.currentView) ||
            (typeof currentView !== 'undefined' && currentView) || '';
        key = String(key).toLowerCase();
        const name = REGISTRY[key];
        if (name) return openHelp(name);
        // try the header module label as a secondary hint
        const hm = document.getElementById('header-module');
        const alt = hm ? REGISTRY[hm.textContent.trim().toLowerCase()] : null;
        return alt ? openHelp(alt) : showIndex();
    }

    // Inline (i) help affordance. Returns an HTML string to drop into any header.
    //   helpIcon('opnsense')                    -> doc's top
    //   helpIcon('opnsense', 'Key commands')    -> scrolls to that ## section
    //   helpIcon('opnsense', null, 'Firewall help') -> custom aria/title label
    function helpIcon(name, section, label) {
        const sec = section ? "'" + String(section).replace(/'/g, "\\'") + "'" : 'null';
        const title = esc(label || 'Help');
        return '<button type="button" class="lm-help-icon" title="' + title + '" aria-label="' + title +
            '" onclick="openHelp(\'' + name + '\',' + sec + ');return false;">i</button>';
    }

    window.openHelp = openHelp;
    window.closeHelp = closeHelp;
    window.helpForCurrentView = helpForCurrentView;
    window.helpIcon = helpIcon;
    window.renderHelpMarkdown = renderMarkdown; // exposed for reuse/testing

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ensureDom);
    } else {
        ensureDom();
    }
})();

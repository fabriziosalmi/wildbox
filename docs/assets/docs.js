// Shared behaviour for docs.html and the pages rendered by _layouts/doc.html.
//
// The page content is HTML that Jekyll produced at build time from the
// Markdown in this repository. Nothing here fetches documents or turns text
// into markup at runtime: the only DOM this script creates is the copy button and its wrapper,
// and it reads code with textContent and writes it with textContent.
(function () {
    'use strict';

    function toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (!sidebar || !overlay) return;
        sidebar.classList.toggle('-translate-x-full');
        overlay.classList.toggle('hidden');
    }

    function addCopyButtons() {
        const blocks = document.querySelectorAll('.markdown-content pre');
        blocks.forEach(function (pre) {
            const code = pre.querySelector('code') || pre;
            if (!pre.parentElement || pre.parentElement.classList.contains('code-wrap')) return;
            // Wrap the block so the button can be positioned over it.
            const holder = document.createElement('div');
            holder.className = 'code-wrap';
            pre.parentElement.insertBefore(holder, pre);
            holder.appendChild(pre);
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'copy-button';
            button.textContent = 'Copy';
            button.setAttribute('aria-label', 'Copy code to clipboard');
            button.addEventListener('click', function () {
                if (!navigator.clipboard) return;
                navigator.clipboard.writeText(code.textContent).then(function () {
                    button.textContent = 'Copied';
                    setTimeout(function () { button.textContent = 'Copy'; }, 2000);
                }, function () {
                    button.textContent = 'Copy failed';
                });
            });
            holder.insertBefore(button, pre);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('[data-toggle-sidebar]').forEach(function (el) {
            el.addEventListener('click', toggleSidebar);
        });
        // Close the off-canvas sidebar after choosing an entry on small screens.
        document.querySelectorAll('#sidebar a').forEach(function (link) {
            link.addEventListener('click', function () {
                const sidebar = document.getElementById('sidebar');
                if (window.innerWidth < 768 && sidebar && !sidebar.classList.contains('-translate-x-full')) {
                    toggleSidebar();
                }
            });
        });
        addCopyButtons();
    });

})();

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

    // "On this page" list for long documents, built from the h2 headings and
    // the ids kramdown gave them. Text is copied with textContent.
    function addTableOfContents() {
        const article = document.querySelector('article.markdown-content');
        if (!article) return;
        const headings = Array.prototype.filter.call(
            article.querySelectorAll('h2[id]'),
            function (h) { return !h.closest('footer'); }
        );
        if (headings.length < 5) return;
        const nav = document.createElement('nav');
        nav.className = 'page-toc';
        nav.setAttribute('aria-label', 'On this page');
        const title = document.createElement('p');
        title.className = 'page-toc-title';
        title.textContent = 'On this page';
        nav.appendChild(title);
        const list = document.createElement('ul');
        headings.forEach(function (h) {
            const item = document.createElement('li');
            const link = document.createElement('a');
            link.href = '#' + encodeURIComponent(h.id);
            link.textContent = h.textContent;
            item.appendChild(link);
            list.appendChild(item);
        });
        nav.appendChild(list);
        const h1 = article.querySelector('h1');
        if (h1 && h1.nextSibling) {
            article.insertBefore(nav, h1.nextSibling);
        } else {
            article.insertBefore(nav, article.firstChild);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        addTableOfContents();
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

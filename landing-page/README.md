# Wildbox Landing Page

Modern, responsive landing page for Wildbox Security Platform.

## 📁 Structure

```
landing-page/
├── index.html          # Main landing page
└── README.md          # This file
```

## 🚀 Usage

### Local Preview
```bash
# Using Python
python3 -m http.server 8000

# Or using Node.js
npx http-server

# Then open: http://localhost:8000/landing-page/
```

### Deploy to GitHub Pages
```bash
# The landing page will be served at:
# https://fabriziosalmi.github.io/wildbox/landing-page/
```

### Deploy to Custom Domain
Copy `index.html` to your web server's root directory.

## 🎨 Design Features

- **Modern Dark Theme**: Professional, contemporary design
- **Responsive**: Mobile-first, works on all devices
- **Fast**: Pure HTML + Tailwind CSS (CDN)
- **No Build Required**: Just serve the HTML file
- **SEO Optimized**: Proper meta tags and structure
- **Smooth Animations**: Subtle hover effects and scroll animations
- **Accessibility**: Semantic HTML, proper contrast ratios

## 📊 Sections

1. **Navigation**: Sticky header with quick links
2. **Hero**: Main value proposition + CTA
3. **Installation**: 3-command setup showcase
4. **Features**: 6 key capability cards
5. **How It Works**: 5-step process flow
6. **Use Cases**: Target audiences
7. **Pricing**: Simple pricing (Free)
8. **CTA**: Final call-to-action
9. **Footer**: Links and legal

## 🎯 Key Features

- ✅ GitHub integration links
- ✅ Installation command showcase
- ✅ Feature cards with hover effects
- ✅ Smooth scrolling navigation
- ✅ Responsive grid layouts
- ✅ Mobile-friendly design
- ✅ Performance optimized
- ✅ No dependencies required

## 🔧 Customization

### Change Colors
Edit the Tailwind CSS classes in `index.html`:
- Primary color: Change `red-600` to your brand color (e.g., `blue-600`)
- Gradients: Update `gradient-text` and gradient backgrounds

### Update Content
Simply edit the HTML text directly. No build process needed.

### Add Custom CSS
Add your styles in the `<style>` tag at the top.

## 📱 Responsive Breakpoints

- **Mobile**: < 768px
- **Tablet**: 768px - 1024px
- **Desktop**: > 1024px

## ⚡ Performance

- **No JavaScript bundles**: ~5KB total size
- **CSS via CDN**: Tailwind CSS loaded from CDN
- **Images**: Emoji and SVG only (no large images)
- **Load time**: < 1 second on broadband

## 🔐 Security

- No external dependencies beyond Tailwind CSS CDN
- No tracking or analytics code
- No form submissions (links only)
- Safe for self-hosting

## 📈 Analytics (Optional)

To add Google Analytics:
```html
<!-- Add before </head> -->
<script async src="https://www.googletagmanager.com/gtag/js?id=YOUR_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'YOUR_ID');
</script>
```

## 🎓 Learning Resources

- [Tailwind CSS](https://tailwindcss.com/)
- [MDN Web Docs](https://developer.mozilla.org/)
- [HTML Semantic Elements](https://www.w3schools.com/html/html5_semantic_elements.asp)

## 📝 License

MIT - Same as Wildbox

## 🤝 Contributing

See main [README.md](../README.md) for contribution guidelines.

---

**Built for Wildbox** - Open-source security operations platform

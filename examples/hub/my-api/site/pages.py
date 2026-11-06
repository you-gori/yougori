"""The website: one page, no frameworks, no outside requests.

Everything the browser loads comes from this sandbox, so the site keeps working
with the sandbox offline and nothing about your users leaves it.

The look follows The Design Society's site (thedesignsociety.fr): a lavender page,
acid lime and electric blue, hairline dividers, small uppercase captions in brackets,
square dots, little browser windows, pill-and-square badges, an arrow "bubble" button,
huge pixel titles and a soft CRT screen. Their commercial fonts are replaced by open
ones served from site/fonts: Geist for text, Kode Mono for labels, Geist Pixel for numbers
and the footer word, and pixel titles rasterised from Tinos on a tiny canvas, then scaled
up with their steps rounded off. Every element is built with createElement and
textContent; no HTML is ever parsed from data.
"""

# Film grain for the CRT screen, served from this site so the content policy holds.
GRAIN = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
    '<filter id="n"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" stitchTiles="stitch"/></filter>'
    '<rect width="100%" height="100%" filter="url(#n)" opacity=".7"/></svg>'
)

CSS = r"""
/* Open fonts served by this site, standing in for the reference's commercial ones:
   Geist for KH Teka (text), Kode Mono for KH Interference (uppercase labels),
   Tinos rasterised for FK Raster Roman (pixel titles), and Geist Pixel exactly as used there. */
@font-face{font-family:"Geist";src:url(/fonts/geist.woff2) format("woff2");font-weight:100 900;font-style:normal;font-display:swap}
@font-face{font-family:"Kode Mono";src:url(/fonts/kode-mono.woff2) format("woff2");font-weight:400 700;font-style:normal;font-display:swap;
  unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Tinos";src:url(/fonts/tinos.woff2) format("woff2");font-weight:400;font-style:normal;font-display:swap;
  unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Geist Pixel Square";src:url(/fonts/geist-pixel-square.woff2) format("woff2");font-weight:400;font-style:normal;font-display:swap}
@font-face{font-family:"Geist Pixel Line";src:url(/fonts/geist-pixel-line.woff2) format("woff2");font-weight:400;font-style:normal;font-display:swap}
:root{
  color-scheme:light;
  --bg:#ebedf5; --paper:#ffffff; --paper-2:#f7f7f7; --ink:#1e1e1e; --ink-2:#66666e; --line:rgba(29,29,29,.15);
  --lime:#bcf015; --blue:#350aff; --orange:#ff4c24; --amber:#f5b800;
  --night:#03000f; --night-2:#040014; --night-3:#05001a; --night-line:rgba(255,255,255,.09); --night-ink:#f0f0f0;
  /* Accent used as text, links and focus (lighter in dark mode); text on lime, amber and orange,
     always dark; warnings written as text on the page. */
  --accent:#350aff; --on-bright:#1e1e1e; --danger-ink:#c2380f; --placeholder:#9a9aa3; --amber-soft:#fff7e0; --skel-1:#e1e3ee; --skel-2:#f3f4f9;
  --focus-ring:rgba(53,10,255,.12); --glare:.06; --title-filter:invert(0); --edge:transparent; --scrim:rgba(3,0,15,.5);
  --r-xs:2px; --r-s:4px; --r-m:6px;
  --s:16px; --m:24px; --l:32px;
  --ease:cubic-bezier(.625,.05,0,1);
  --sans:"Geist","Helvetica Neue",Helvetica,Arial,sans-serif;
  --label:"Kode Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --mono:"Kode Mono",ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;
  --pixel:"Geist Pixel Square","Kode Mono",ui-monospace,monospace;
  --pixel-line:"Geist Pixel Line","Geist Pixel Square","Kode Mono",monospace;
}
/* Dark mode: the device's setting unless the person picked one (the switch in the menu).
   Every text meets WCAG contrast (4.5:1) in both themes, tests/theme-ui.cjs checks it; body
   text is about 15:1, and accents used as text get a lighter blue. */
:root[data-theme="dark"]{color-scheme:dark;--bg:#0f1014;--paper:#17181e;--paper-2:#1d1f26;--ink:#eceef4;--ink-2:#a5a9b8;--line:rgba(255,255,255,.13);--accent:#a493ff;--danger-ink:#ff7a5c;--placeholder:#7f8394;--amber-soft:#2a2310;--skel-1:#22242c;--skel-2:#2c2f38;--focus-ring:rgba(164,147,255,.28);--glare:.025;--title-filter:invert(1);--edge:rgba(255,255,255,.1);--scrim:rgba(0,0,0,.66)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#0f1014;--paper:#17181e;--paper-2:#1d1f26;--ink:#eceef4;--ink-2:#a5a9b8;--line:rgba(255,255,255,.13);--accent:#a493ff;--danger-ink:#ff7a5c;--placeholder:#7f8394;--amber-soft:#2a2310;--skel-1:#22242c;--skel-2:#2c2f38;--focus-ring:rgba(164,147,255,.28);--glare:.025;--title-filter:invert(1);--edge:rgba(255,255,255,.1);--scrim:rgba(0,0,0,.66)}}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--bg);-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:14px/1.45 var(--sans);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;overflow-x:clip}
a{color:inherit}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
::selection{background:var(--lime);color:var(--on-bright)}
/* Who speaks in which voice: labels in the monospaced capitals, code in the same mono. */
.caption,.brackets,.nav-name,.nav-where,.nav-link,.nav-email,.win-title,.win-plus,.bubble-label,.bracket,.flat,.toggle,.sq,.rd,.tag,.label,
.select,.toolbar .count,.mcard-price span,th,.group-row td,.fact,.night-about,.pcard-price,.stat-hint,.foot-links,.foot-about,.toast-bar,
.veil-text,.auth .switch{font-family:var(--label)}
.mono,.mcard-index,.mcard-id,.addr,.code pre,.secret code,kbd,.input.mono{font-family:var(--mono)}
.select.wide{font-family:var(--sans)}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}

/* The CRT screen: scanlines, vignette, glare and grain over everything, never in the way of a click. */
.crt{position:fixed;inset:0;pointer-events:none;z-index:9000;overflow:hidden}
.crt>div{position:absolute;inset:0}
.crt .crt-grain{inset:-50%;background-image:url(/grain.svg);background-size:200px 200px;opacity:.05;animation:grain .4s steps(4) infinite}
.crt-vignette{background:radial-gradient(ellipse 130% 90% at 50% 50%,transparent 65%,rgba(0,0,0,.2) 100%)}
.crt-glare{background:radial-gradient(ellipse 80% 50% at 30% 20%,rgba(255,255,255,var(--glare)),transparent 60%)}
.crt-scan{background:repeating-linear-gradient(to bottom,rgba(0,0,0,.06) 0,rgba(0,0,0,.06) 1px,transparent 1px,transparent 3px)}
.crt-bezel{box-shadow:inset 0 0 60px 10px rgba(0,0,0,.16),inset 0 0 160px 40px rgba(0,0,0,.07)}
@keyframes grain{0%,100%{transform:translate(0,0)}25%{transform:translate(-3%,2%)}50%{transform:translate(2%,-3%)}75%{transform:translate(-2%,-2%)}}
@media (max-width:768px){.crt .crt-grain{display:none}.crt-scan{background:repeating-linear-gradient(to bottom,rgba(0,0,0,.045) 0,rgba(0,0,0,.045) 1px,transparent 1px,transparent 4px)}}

/* Pixel type: canvases scaled by whole pixels, with a faint RGB split like an old screen. */
.px{width:100%;--px:6px}
.px-wait{visibility:hidden}
.px-row{display:flex;align-items:center;gap:calc(var(--px) * 1.5)}
.px-row+.px-row{margin-top:calc(var(--px) * -1.5)}
.px-center .px-row{justify-content:center}
.px-slot,.px canvas{display:block;flex:none}
.px.rgb canvas{filter:drop-shadow(1px 0 0 rgba(255,0,72,.32)) drop-shadow(-1px 0 0 rgba(0,170,255,.32))}
.px.ink canvas{filter:var(--title-filter)}
.px.ink.rgb canvas{filter:var(--title-filter) drop-shadow(1px 0 0 rgba(255,0,72,.32)) drop-shadow(-1px 0 0 rgba(0,170,255,.32))}
.px-fallback{font-family:Tinos,"Times New Roman",Times,serif;font-size:calc(var(--px) * 12);line-height:1;letter-spacing:-.02em}
.px-fallback.sans{font-family:var(--sans)}
.eye{display:block;width:clamp(76px,9vw,132px);height:auto;color:var(--ink);overflow:visible}
.eye .iris{animation:iris 12s ease-in-out infinite}
.eye .pupil{fill:var(--on-bright)}
.eye-look{transition:transform .3s steps(3)}
@keyframes iris{0%,100%{fill:#bcf015}50%{fill:#350aff}}

/* Two-step navigation: a small floating bar that opens into big links. */
.nav{position:fixed;top:var(--s);left:var(--s);z-index:60;width:min(25em,calc(100vw - 2 * var(--s)))}
.nav-bar{background:var(--paper);border:1px solid var(--line);border-radius:var(--r-m);box-shadow:0 14px 40px -24px rgba(3,0,15,.45)}
.nav-top{display:flex;align-items:center;gap:10px;height:3.5em;padding:0 .6em 0 .8em;position:relative}
.nav-top::after{content:"";position:absolute;left:.5em;right:.5em;bottom:0;height:1px;background:var(--line);opacity:0;transition:opacity .3s}
.nav.open .nav-top::after{opacity:1}
.nav-brand{display:flex;align-items:center;gap:10px;background:none;border:0;padding:0;cursor:pointer;min-width:0;flex:1;text-align:left}
.mark{width:24px;height:24px;border-radius:var(--r-xs);background:var(--lime);color:var(--blue);display:grid;place-items:center;flex:none}
.mark svg{width:12px;height:12px}
.nav-name{font-size:12px;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-where{font-size:11px;text-transform:uppercase;letter-spacing:.02em;color:var(--ink-2);white-space:nowrap}
.nav-toggle{width:2.5em;height:2.5em;display:grid;place-items:center;background:none;border:0;cursor:pointer;position:relative;flex:none}
.nav-toggle i{position:absolute;width:1.6em;height:2px;background:var(--ink);transition:transform .6s var(--ease)}
.nav-toggle i:first-child{transform:translateY(-3px)}
.nav-toggle i:last-child{transform:translateY(3px)}
.nav.open .nav-toggle i:first-child{transform:rotate(45deg)}
.nav.open .nav-toggle i:last-child{transform:rotate(-45deg)}
.nav-panel{display:grid;grid-template-rows:0fr;transition:grid-template-rows .7s var(--ease)}
.nav.open .nav-panel{grid-template-rows:1fr}
.nav-panel>div{overflow:hidden;min-height:0}
.nav-links{list-style:none;margin:0;padding:.8em .8em .5em}
.nav-link{background:none;border:0;padding:.1em 0;font-size:1.9em;letter-spacing:-.04em;line-height:1.05;text-transform:uppercase;cursor:pointer;display:flex;align-items:center;gap:.3em;text-align:left;color:var(--ink)}
.nav-link:hover{color:var(--accent)}
.nav-link[aria-current="page"]::before{content:"";width:.28em;height:.28em;background:var(--accent);flex:none}
.nav-small{list-style:none;margin:0;padding:.7em .8em 1em;display:flex;flex-wrap:wrap;gap:8px 16px;border-top:1px solid var(--line)}
.nav-email{font-size:11px;text-transform:uppercase;color:var(--ink-2);letter-spacing:.02em}
.quick{position:absolute;top:var(--s);right:var(--s);z-index:50;display:flex;align-items:center;gap:14px;background:var(--paper);
  border:1px solid var(--line);border-radius:var(--r-m);padding:7px 8px 7px 14px;box-shadow:0 14px 40px -26px rgba(3,0,15,.45)}
.quick .bracket[aria-current="page"]{color:var(--accent);text-decoration:underline;text-underline-offset:3px}
.nav-admin{display:none}
@media (max-width:1080px){.quick{display:none}.nav-admin{display:inline-flex}}
@media (max-width:520px){.nav-where{display:none}}

/* Page layout */
main{flex:1;width:100%;max-width:1440px;margin:0 auto;padding:7.5em var(--m) 5em;position:relative}
@media (max-width:640px){main{padding:6.25em var(--s) 4em}}
main:has(> .night:last-child){padding-bottom:0}
.view-in{animation:viewin .55s var(--ease) both}
@keyframes viewin{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.caption{display:flex;align-items:center;gap:6px;font-size:13px;text-transform:uppercase;line-height:1;letter-spacing:.01em}
.dot{display:inline-block;width:8px;height:8px;background:var(--accent);flex:none}
.dot.lime,.dot.green{background:var(--lime)}
.dot.orange,.dot.red{background:var(--orange)}
.dot.amber{background:var(--amber)}
.dot.ink{background:var(--ink)}
.brackets{display:flex;justify-content:center;gap:.45em;font-size:13px;text-transform:uppercase;letter-spacing:.02em;white-space:nowrap;line-height:1;overflow:hidden;max-width:100%}
.brackets-text{overflow:hidden;text-overflow:ellipsis}
.statement{font-size:clamp(28px,3.7vw,56px);line-height:.98;letter-spacing:-.04em;font-weight:400;margin:14px 0 0;max-width:19em}
.statement.s{font-size:clamp(20px,2.3vw,34px);line-height:1.04;max-width:26em}
.page-head{margin:0 0 var(--l)}
.page-head-top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.page-head .px{margin:22px 0 4px}
.divider{height:1px;background:var(--line)}
.section{margin-top:clamp(44px,8vh,88px)}
.section-head{margin-bottom:22px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:var(--s);align-items:start}
.grid2.tight{gap:0 var(--s)}
.bleed{width:100vw;margin-left:calc(50% - 50vw)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.row.end{justify-content:flex-end;flex-wrap:nowrap}
.row.center{justify-content:center}
.spacer{flex:1}
.stack{display:flex;flex-direction:column;gap:14px}
.muted{color:var(--ink-2)}
.small{font-size:12px}
.mono{font-family:var(--mono);font-size:12.5px}
.num{font-variant-numeric:tabular-nums}
.break{word-break:break-all}
.note{margin:14px 2px 0;font-size:12px;color:var(--ink-2)}
.link{background:none;border:0;padding:0;cursor:pointer;text-decoration:underline;text-underline-offset:3px;color:inherit}
.link:hover{color:var(--accent)}

/* Little browser windows */
.win{background:var(--paper-2);border:1px solid var(--line);border-radius:var(--r-s);padding:0 6px 6px;display:flex;flex-direction:column;min-width:0}
.win-dots{display:flex;align-items:center;gap:4px;height:15px;padding:0 1px}
.win-dots i{width:6px;height:6px;border-radius:50%;background:var(--paper);border:1px solid var(--line)}
.win-bar{display:flex;justify-content:space-between;align-items:center;gap:10px;background:var(--paper);border:1px solid var(--line);
  border-radius:var(--r-xs) var(--r-xs) 0 0;padding:10px;min-height:34px}
.win-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;line-height:1}
.win-plus{font-size:10px;font-weight:700;line-height:1}
.win-body{background:var(--paper);border:1px solid var(--line);border-top:0;border-radius:0 0 var(--r-xs) var(--r-xs);padding:18px;flex:1;min-width:0}
.win-body.flush{padding:0}
.win-body:not(:last-child){border-radius:0}
.win-foot{display:flex;gap:8px;align-items:flex-start;background:var(--paper);border:1px solid var(--line);border-top:1px dashed var(--line);
  border-radius:0 0 var(--r-xs) var(--r-xs);padding:12px 16px;font-size:12px;color:var(--ink-2)}
.win-foot svg{width:9px;height:9px;flex:none;margin-top:4px;color:var(--accent)}
.win-foot>span{flex:1;min-width:0}
.win-foot a{color:var(--ink)}
.win.night{background:var(--night-3);border-color:var(--night-line)}
.win.night .win-dots i{background:var(--night-2);border-color:var(--night-line)}
.win.night .win-bar,.win.night .win-body,.win.night .win-foot{background:var(--night-2);border-color:var(--night-line);color:var(--night-ink)}
.win.lime{background:var(--lime);border-color:rgba(29,29,29,.28)}
.win.lime .win-dots i{background:var(--lime);border-color:rgba(29,29,29,.35)}
.win.blue{background:var(--blue);border-color:rgba(255,255,255,.2)}
.win.blue .win-dots i{background:var(--blue);border-color:rgba(255,255,255,.4)}

/* Buttons */
.bubble{--h:44px;position:relative;display:inline-flex;align-items:center;border:0;padding:0;background:none;cursor:pointer;border-radius:10em;flex:none}
.bubble-arrow{width:var(--h);height:var(--h);border-radius:10em;background:var(--lime);color:var(--on-bright);display:grid;place-items:center;flex:none;
  transform:scale(0) rotate(.001deg);transform-origin:left;transition:transform .735s var(--ease)}
.bubble-arrow svg{width:36%;height:36%;transition:transform .735s var(--ease)}
.bubble-arrow.dup{position:absolute;right:0;top:0;transform:scale(1) rotate(.001deg);transform-origin:right;z-index:2}
.bubble-label{height:var(--h);display:flex;align-items:center;padding:0 1.5em;border-radius:var(--r-m);background:var(--blue);color:#fff;
  font-size:12px;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap;line-height:1;transform:translateX(calc(-1 * var(--h))) rotate(.001deg);transition:transform .735s var(--ease)}
.bubble:not([disabled]):hover .bubble-label,.bubble:not([disabled]):focus-visible .bubble-label{transform:translateX(0) rotate(.001deg)}
.bubble:not([disabled]):hover .bubble-arrow,.bubble:not([disabled]):focus-visible .bubble-arrow{transform:scale(1) rotate(.001deg)}
.bubble:not([disabled]):hover .bubble-arrow.dup,.bubble:not([disabled]):focus-visible .bubble-arrow.dup{transform:scale(0) rotate(.001deg)}
.bubble:not([disabled]):hover .bubble-arrow svg{transform:rotate(-45deg)}
.bubble.lime .bubble-label{background:var(--lime);color:var(--on-bright)}
.bubble.lime .bubble-arrow{background:var(--blue);color:#fff}
.bubble.danger .bubble-label{background:var(--orange);color:var(--on-bright)}
.bubble.small{--h:34px}
.bubble.small .bubble-label{font-size:11px;padding:0 1.1em}
.bubble[disabled]{opacity:.45;cursor:not-allowed}
.bracket{background:none;border:0;padding:4px 0;font-size:11px;text-transform:uppercase;letter-spacing:.03em;line-height:1;cursor:pointer;white-space:nowrap;color:var(--ink)}
.bracket::before{content:"["}
.bracket::after{content:"]"}
.bracket:hover{color:var(--accent)}
.bracket.danger{color:var(--danger-ink)}
.bracket.light{color:#fff}
.bracket.light:hover{color:var(--lime)}
.flat{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:30px;padding:0 11px;border:1px solid transparent;border-radius:var(--r-xs);
  background:var(--lime);color:var(--on-bright);font-size:11px;text-transform:uppercase;letter-spacing:.03em;line-height:1;cursor:pointer;white-space:nowrap;
  transition:background .2s,color .2s,border-color .2s}
.flat:hover{background:var(--on-bright);color:var(--lime)}
.flat.blue{background:var(--blue);color:#fff}
.flat.blue:hover{background:var(--on-bright);color:#fff}
.flat.danger{background:transparent;border-color:var(--danger-ink);color:var(--danger-ink)}
.flat.danger:hover{background:var(--orange);border-color:var(--orange);color:var(--on-bright)}
.flat[disabled]{opacity:.45;cursor:not-allowed}
.toggles{display:flex;flex-wrap:wrap;gap:4px}
.toggle{border:1px solid var(--line);background:var(--paper);border-radius:var(--r-xs);padding:7px 9px;font-size:11px;text-transform:uppercase;
  letter-spacing:.03em;line-height:1;cursor:pointer;color:var(--ink);white-space:nowrap;font-variant-numeric:tabular-nums}
.toggle:hover{border-color:var(--ink)}
.toggle[aria-pressed="true"]{background:var(--blue);border-color:var(--blue);color:#fff}
.toggle.lime[aria-pressed="true"]{background:var(--lime);border-color:var(--lime);color:var(--on-bright)}

/* Badges: a square and a pill side by side */
.pair{display:inline-flex;align-items:center;border:0;padding:0;background:none}
button.pair{cursor:pointer}
.sq,.rd,.tag{display:inline-flex;align-items:center;padding:4px 6px;font-size:11px;text-transform:uppercase;letter-spacing:.02em;line-height:1;white-space:nowrap}
.sq,.tag{border-radius:var(--r-xs)}
.rd,.tag.round{border-radius:999px}
.pair .sq,.pair .rd,.tag{background:var(--lime);color:var(--on-bright)}
.pair.blue .sq,.pair.blue .rd,.tag.blue{background:var(--blue);color:#fff}
.pair.orange .sq,.pair.orange .rd,.tag.orange{background:var(--orange);color:var(--on-bright)}
.pair.ink .sq,.pair.ink .rd,.tag.ink{background:var(--ink);color:var(--bg)}
.pair.paper .sq,.pair.paper .rd,.tag.paper{background:var(--paper);color:var(--ink);box-shadow:inset 0 0 0 1px var(--line)}
.tag.amber{background:var(--amber);color:var(--on-bright)}

/* Forms */
.field{display:flex;flex-direction:column;gap:7px;margin-bottom:16px;min-width:0}
.label{font-size:11px;text-transform:uppercase;letter-spacing:.03em;line-height:1}
.input,.select{width:100%;height:40px;padding:0 14px;border:1px solid var(--line);border-radius:var(--r-s);background:var(--paper-2);color:var(--ink);font-size:14px;
  transition:border-color .2s,background .2s,box-shadow .2s}
.input::placeholder{color:var(--placeholder)}
.input:focus,.select:focus{outline:none;border-color:var(--accent);background:var(--paper);box-shadow:0 0 0 3px var(--focus-ring)}
.input.mono{font-family:var(--mono);font-size:13px}
.input.compact{height:32px;width:100px;padding:0 9px;font-size:13px}
.select{width:auto;padding-right:28px;font-size:12px;text-transform:uppercase;letter-spacing:.02em;height:34px}
.select.wide{width:100%;height:40px;font-size:13px;text-transform:none;letter-spacing:0}
.address{display:flex;align-items:center;gap:12px;border:1px solid var(--line);border-radius:var(--r-s);background:var(--paper-2);padding:0 12px;height:40px;min-width:0}
.address.grow{flex:1;min-width:220px;max-width:460px}
.address svg{width:13px;height:13px;color:var(--ink-2);flex:none}
.address input{border:0;background:transparent;font-size:14px;outline:none;flex:1;min-width:0;color:var(--ink)}
.address input::placeholder{color:var(--placeholder)}
.address:focus-within{border-color:var(--accent);background:var(--paper);box-shadow:0 0 0 3px var(--focus-ring)}
.address kbd{font-family:var(--mono);font-size:11px;color:var(--ink-2);border:1px solid var(--line);border-radius:var(--r-xs);padding:1px 5px;background:var(--paper)}
.help{font-size:12px;color:var(--ink-2);margin:0}
.secret{display:flex;align-items:center;gap:12px;border:1px solid var(--line);border-radius:var(--r-s);padding:10px 14px;background:var(--paper-2);min-width:0}
.secret code{font-family:var(--mono);font-size:13px;flex:1;word-break:break-all}

/* Callouts, empty states, loading */
.callout{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:var(--r-s);padding:12px 14px;font-size:13.5px;background:var(--paper)}
.callout>.dot{margin-top:5px}
.callout>div{min-width:0;overflow-wrap:anywhere}
.callout.green{background:var(--lime);border-color:rgba(29,29,29,.2);color:var(--on-bright)}
.callout.amber{background:var(--amber-soft);border-color:rgba(245,184,0,.6)}
.callout.red{background:var(--orange);border-color:var(--orange);color:var(--on-bright)}
.callout.red>.dot{background:var(--on-bright)}
.callout.blue{background:var(--paper)}
.notice{margin:0 0 22px}
.empty{text-align:center;padding:48px 20px;color:var(--ink-2)}
.empty-mark{width:28px;height:28px;margin:0 auto 14px;color:var(--accent)}
.empty-mark svg{width:100%;height:100%}
.empty h3{color:var(--ink);margin:0 0 6px;font-size:22px;font-weight:400;letter-spacing:-.03em}
.empty p{margin:0 auto;max-width:34em;font-size:13px}
.empty .row{margin-top:18px}
.loading{display:flex;flex-direction:column;gap:12px;padding:18px}
.loading .bar{height:12px;border-radius:var(--r-xs);background:linear-gradient(90deg,var(--skel-1),var(--skel-2),var(--skel-1));background-size:200% 100%;animation:shimmer 1.2s linear infinite}
@keyframes shimmer{from{background-position:200% 0}to{background-position:-200% 0}}

/* The model list */
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 18px}
.toolbar .count{margin-left:auto;font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.toolbar .count::before{content:"["}
.toolbar .count::after{content:"]"}
.mlist{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:var(--s)}
@media (max-width:1180px){.mlist{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:880px){.mlist{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:560px){.mlist{grid-template-columns:minmax(0,1fr)}}
.mlist>.empty,.mlist>.loading,.mlist>.callout{grid-column:1 / -1}
.mcard{position:relative;display:flex;flex-direction:column;gap:12px;min-width:0;background:var(--paper);border:1px solid var(--line);border-radius:var(--r-m);
  padding:14px 14px 12px;transition:border-color .25s,transform .45s var(--ease),box-shadow .45s var(--ease)}
.mcard:hover{border-color:var(--ink);transform:translateY(-3px);box-shadow:0 18px 38px -26px rgba(3,0,15,.5)}
.mcard::after{content:"";position:absolute;top:-1px;right:-1px;width:10px;height:10px;background:var(--lime);border-radius:0 var(--r-m) 0 0;opacity:0;transition:opacity .25s}
.mcard:hover::after{opacity:1}
.mcard-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.mcard-index{font-family:var(--mono);font-size:11px;color:var(--ink-2)}
.mcard-tags{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.mcard-name{font-size:22px;letter-spacing:-.035em;line-height:1.05;word-break:break-word}
.mcard-id{font-family:var(--mono);font-size:11px;color:var(--ink-2);margin-top:6px;word-break:break-all}
.mcard-price{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:auto;padding-top:12px;border-top:1px dashed var(--line)}
.mcard-price b{display:block;font-size:19px;font-weight:400;letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.mcard-price span{display:block;font-family:var(--label);font-size:10px;text-transform:uppercase;letter-spacing:.03em;color:var(--ink-2);margin-top:2px}
.mcard-price .whole{grid-column:1 / -1}
.mcard-foot{display:flex;justify-content:flex-end}
.mcard.off{opacity:.62}

/* Tables */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:12px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:13px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--paper-2)}
td.right,th.right{text-align:right}
.group-row td{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:var(--ink-2);background:var(--paper-2);padding:9px 14px}
.price-tools{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:14px;border-bottom:1px solid var(--line)}
.price-tools .address{max-width:360px}
.price-hint{padding:14px 14px 0}
.stack-tight{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
.markup{display:flex;align-items:center;gap:8px}

/* Code in a browser window */
.code .win-body{overflow:hidden}
.addr-row{display:flex;align-items:center;gap:14px;padding:10px 12px;border-bottom:1px solid var(--night-line)}
.lights{display:flex;gap:6px;flex:none}
.lights i{width:10px;height:10px;border-radius:50%;border:1px solid var(--night-line);background:var(--night-3)}
.addr{display:flex;align-items:center;gap:10px;flex:1;min-width:0;border:1px solid var(--night-line);background:var(--night-3);border-radius:var(--r-s);padding:7px 12px;
  font-family:var(--mono);font-size:12px;color:#c9c9d6}
.addr span{flex:1;min-width:0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.addr svg{width:12px;height:12px;flex:none;color:#8d8da0}
.code-tabs{display:flex;gap:8px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--night-line)}
.code-tabs .toggle{background:transparent;border-color:var(--night-line);color:#c9c9d6}
.code-tabs .toggle:hover{border-color:#c9c9d6}
.code-tabs .toggle[aria-pressed="true"]{background:var(--lime);border-color:var(--lime);color:var(--on-bright)}
.code-tabs .bracket{color:#c9c9d6}
.code-tabs .bracket:hover{color:var(--lime)}
.code pre{margin:0;padding:18px;overflow:auto;font-family:var(--mono);font-size:12.8px;line-height:1.65;color:var(--night-ink);white-space:pre;tab-size:2}

/* Main page: a small title line, then the models */
.hero{display:flex;flex-direction:column;gap:14px}
.hero-row{display:flex;align-items:center;justify-content:space-between;gap:12px 24px;flex-wrap:wrap}
.hero-title{display:flex;align-items:center;gap:7px;margin:0;font-family:var(--label);font-size:13px;font-weight:400;text-transform:uppercase;letter-spacing:.01em;line-height:1}
.hero .eye{width:52px}
.hero-lede{margin:0;flex:1;min-width:260px;max-width:46em;font-size:14px;color:var(--ink-2)}
.hero-facts,.hero-cta{display:flex;align-items:center;gap:6px 8px;flex-wrap:wrap}
.hero-cta{gap:10px 16px}
.hero .toolbar{margin:10px 0 4px}
.night{background:var(--night);color:var(--night-ink);margin-top:clamp(44px,8vh,88px);box-shadow:inset 0 1px 0 var(--edge)}
.night-inner{max-width:1440px;margin:0 auto;padding:clamp(64px,12vh,140px) var(--m) clamp(28px,5vh,48px)}
.night-text{font-size:min(4.2vw,6vh);line-height:1.04;letter-spacing:-.035em;margin:0;max-width:21em}
.night-about{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-top:clamp(48px,10vh,120px);font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#ebedf5}
.night-about .right{text-align:right}
.dim{opacity:.8}
@media (max-width:640px){.night-text{font-size:28px}}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,240px),1fr));gap:var(--s)}
.pcard{position:relative;background:#131313;color:var(--night-ink);box-shadow:inset 0 0 0 1px var(--edge);border-radius:var(--r-m);aspect-ratio:4/5;overflow:hidden;padding:16px;display:flex;flex-direction:column;justify-content:space-between}
.pcard>*:not(.pcard-pixels){position:relative;z-index:1}
.pcard-pixels{position:absolute;inset:0;display:grid;grid-template-columns:repeat(6,1fr);grid-template-rows:repeat(8,1fr);pointer-events:none;z-index:2}
.pcard-pixels i{background:currentColor;opacity:0}
.pcard:hover .pcard-pixels i{animation:pix .42s steps(1) var(--d,0ms) both}
@keyframes pix{0%{opacity:1}100%{opacity:0}}
.pcard.lime{color:var(--lime)}
.pcard.orange{color:var(--orange)}
.pcard.blue{color:#6d4dff}
.pcard.ink,.pcard.paper{color:#ebedf5}
.pcard-foot{display:flex;flex-direction:column;gap:8px;color:var(--night-ink)}
.pcard-price{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#ebedf5}

/* Credits and admin */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:var(--l) var(--s)}
.stat{border-top:1px solid var(--ink);padding-top:14px;min-width:0}
.stat-value{font-family:var(--pixel);font-size:clamp(40px,4.4vw,66px);line-height:1;margin:18px 0 10px;overflow-wrap:anywhere}
.stat-hint{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--ink-2)}
.setup-card{margin-bottom:var(--l)}
.steps{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr));gap:var(--s)}
.steps li{border-top:1px solid var(--ink);padding-top:14px;display:flex;flex-direction:column;gap:10px}
.step-head{display:flex;justify-content:space-between;align-items:center;gap:10px}
.step-title{font-size:22px;letter-spacing:-.035em;line-height:1.05}
.steps li.done .step-title{color:var(--ink-2)}
.chooser{display:flex;flex-direction:column;gap:12px}
.status-row td:first-child{white-space:nowrap}
.status-name{display:flex;align-items:center;gap:8px}
.fix{margin-top:6px;display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 12px}
.fix code{font-family:var(--mono);font-size:11px;overflow-wrap:anywhere}
.dialog-field{margin-top:18px}

/* Sign in and sign up */
.auth{max-width:460px;margin:2vh auto 0;display:flex;flex-direction:column;gap:22px}
.auth .px{margin:0}
.auth .switch{text-align:center;font-size:12px;text-transform:uppercase;letter-spacing:.03em}

/* Footer */
.foot{background:var(--blue);color:#fff;position:relative;overflow:hidden}
.foot-inner{max-width:1440px;margin:0 auto;padding:var(--l) var(--m) var(--m);display:flex;flex-direction:column;gap:var(--l)}
.foot-wins{display:flex;gap:var(--s);flex-wrap:wrap;align-items:flex-start}
.foot-wins .win{width:240px;color:var(--ink)}
.foot-links{display:flex;flex-direction:column;align-items:flex-start;gap:6px}
.foot-links span{font-size:11px;text-transform:uppercase;letter-spacing:.02em}
.foot-mark{margin:var(--m) 0 calc(-1 * var(--m));font-family:var(--pixel-line);font-size:120px;line-height:.82;height:.5em;overflow:hidden;white-space:nowrap;
  text-align:center;text-transform:uppercase;color:#fff}
.foot-about{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#ebedf5}
.foot-about .right{text-align:right}

/* Notices and dialogs */
.toasts{position:fixed;right:var(--s);bottom:var(--s);z-index:80;display:flex;flex-direction:column;gap:8px;width:min(340px,calc(100vw - 32px))}
.toast{background:var(--night-2);color:var(--night-ink);border:1px solid var(--night-line);border-radius:var(--r-s);overflow:hidden;
  box-shadow:0 18px 50px -20px rgba(3,0,15,.7);animation:toast .5s var(--ease) both}
.toast-bar{display:flex;align-items:center;gap:7px;padding:9px 12px;border-bottom:1px solid var(--night-line);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.toast-body{padding:12px;font-size:13.5px;line-height:1.4}
.toast.bad{background:var(--orange);border-color:var(--orange);color:var(--on-bright)}
.toast.bad .toast-bar{border-color:rgba(0,0,0,.2)}
.toast.bad .dot{background:var(--on-bright)}
@keyframes toast{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
dialog{border:0;padding:0;background:transparent;width:min(480px,calc(100vw - 32px));color:var(--ink);overflow:visible}
dialog::backdrop{background:rgba(3,0,15,.5);background:var(--scrim,rgba(3,0,15,.5))}
.dialog-title{font-size:28px;font-weight:400;letter-spacing:-.04em;line-height:1.02;margin:0}
.dialog-text{margin:12px 0 0;color:var(--ink-2)}
.dialog-actions{margin-top:24px;gap:18px}

/* First load: a curtain of blue pixels that falls apart */
.veil{position:fixed;inset:0;z-index:9500;display:grid;pointer-events:none}
.veil i{background:var(--blue);transition:opacity 0s linear}
.veil.out i{opacity:0}
.veil-text{position:fixed;left:0;right:0;bottom:3.5em;z-index:9501;text-align:center;color:#fff;font-size:12px;text-transform:uppercase;letter-spacing:.06em;pointer-events:none;transition:opacity .2s}
.veil-text.out{opacity:0}

@media (prefers-reduced-motion:reduce){
  .crt .crt-grain,.eye .iris,.loading .bar,.toast,.view-in{animation:none}
  .bubble-arrow,.bubble-label,.bubble-arrow svg,.nav-panel,.nav-toggle i,.eye-look{transition:none}
}
"""

# Loaded in <head>, before the page paints, so a theme the person picked never flashes the
# other one first. The content policy allows no inline script, hence its own small file.
THEME_SCRIPT = """"use strict";
try {
  const theme = localStorage.getItem("theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch {
  // No storage: the device's setting applies.
}
"""

SCRIPT = r"""
"use strict";
const $ = (selector, root = document) => root.querySelector(selector);
const text = value => String(value ?? "");
const known = (table, key) => Object.prototype.hasOwnProperty.call(table, key);
const reducedMotion = () => Boolean(window.matchMedia?.("(prefers-reduced-motion: reduce)").matches);

// ---- Light or dark: the device decides unless the person picks one -----------------------
// theme.js applies a saved choice before the page paints; this keeps it and the switch in step.
const darkQuery = window.matchMedia?.("(prefers-color-scheme: dark)");
const systemTheme = () => darkQuery?.matches ? "dark" : "light";
let themeChoice = (() => {
  try {
    const saved = localStorage.getItem("theme");
    return saved === "light" || saved === "dark" ? saved : null;
  } catch {
    return null;
  }
})();
const currentTheme = () => themeChoice || systemTheme();
function applyTheme() {
  if (themeChoice) document.documentElement.dataset.theme = themeChoice;
  else delete document.documentElement.dataset.theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = currentTheme() === "dark" ? "#0f1014" : "#ebedf5";
}
function switchTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  // Picking what the device already shows means following the device again.
  themeChoice = next === systemTheme() ? null : next;
  try {
    if (themeChoice) localStorage.setItem("theme", themeChoice);
    else localStorage.removeItem("theme");
  } catch {
    // Without storage the choice lasts until the page is closed.
  }
  applyTheme();
  paintChrome();
}
const themeSwitch = () => {
  const dark = currentTheme() === "dark";
  return bracket(dark ? "light mode" : "dark mode", switchTheme, {aria: dark ? "Switch to light mode" : "Switch to dark mode"});
};
applyTheme();
darkQuery?.addEventListener?.("change", () => {
  applyTheme();
  paintChrome();
});
const finePointer = () => Boolean(window.matchMedia?.("(pointer: fine)").matches);

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (key === "value") node.value = value;
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false || kid === "") continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(text(kid)));
  }
  return node;
}

// ---- Pixel icons: tiny bitmaps drawn as SVG squares ----------------------------
const SVG_NS = "http://www.w3.org/2000/svg";
const PIXELS = {
  arrow: ["0001000", "0000100", "0000010", "1111111", "0000010", "0000100", "0001000"],
  plus: ["0001000", "0001000", "0001000", "1111111", "0001000", "0001000", "0001000"],
  check: ["0000000", "0000001", "0000011", "1000110", "1101100", "0111000", "0010000"],
  search: ["01110000", "10001000", "10001000", "10001000", "01110000", "00001100", "00000110", "00000011"],
  globe: ["0011100", "0101010", "1111111", "1001001", "1111111", "0101010", "0011100"],
  refresh: ["0011101", "0100011", "1000111", "1000000", "1000001", "0100010", "0011100"],
  star: ["1001001", "0101010", "0011100", "1111111", "0011100", "0101010", "1001001"],
};
function svgNode(tag, attributes) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  return node;
}
function drawBitmap(rows, parent, on = "1") {
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length;) {
      if (row[x] !== on) { x += 1; continue; }
      let end = x;
      while (row[end] === on) end += 1;
      parent.append(svgNode("rect", {x, y, width: end - x, height: 1}));
      x = end;
    }
  });
}
function pixelIcon(name) {
  const rows = PIXELS[name] || PIXELS.plus;
  const svg = svgNode("svg", {viewBox: `0 0 ${rows[0].length} ${rows.length}`, "shape-rendering": "crispEdges", fill: "currentColor", "aria-hidden": "true", focusable: "false"});
  drawBitmap(rows, svg);
  return svg;
}
const EYE_LINE = [".......#####.......", "....###.....###....", "..##...........##..", ".#...............#.", "#.................#", "#.................#",
  "#.................#", ".#...............#.", "..##...........##..", "....###.....###....", ".......#####......."];
const EYE_IRIS = ["", "", "", "........###", ".......#####", ".......#####", ".......#####", "........###"];
function eye() {
  const svg = svgNode("svg", {viewBox: "0 0 19 11", class: "eye", "shape-rendering": "crispEdges", "aria-hidden": "true", focusable: "false"});
  const outline = svgNode("g", {fill: "currentColor"});
  drawBitmap(EYE_LINE, outline, "#");
  const look = svgNode("g", {class: "eye-look"});
  const iris = svgNode("g", {class: "iris", fill: "#bcf015"});
  drawBitmap(EYE_IRIS, iris, "#");
  look.append(iris, svgNode("rect", {x: 9, y: 5, width: 1, height: 1, fill: "currentColor", class: "pupil"}), svgNode("rect", {x: 8, y: 4, width: 1, height: 1, fill: "#ffffff"}));
  svg.append(outline, look);
  return svg;
}
let eyeFrame = 0;
document.addEventListener("pointermove", event => {
  if (eyeFrame || reducedMotion()) return;
  eyeFrame = requestAnimationFrame(() => {
    eyeFrame = 0;
    for (const node of document.querySelectorAll(".eye")) {
      const box = node.getBoundingClientRect();
      if (!box.width) continue;
      const dx = event.clientX - (box.left + box.width / 2);
      const dy = event.clientY - (box.top + box.height / 2);
      const length = Math.hypot(dx, dy) || 1;
      const x = Math.round(dx / length * Math.min(3, length / 60));
      const y = Math.round(dy / length * Math.min(1, length / 90));
      const look = node.querySelector(".eye-look");
      if (look) look.style.transform = `translate(${x}px, ${y}px)`;
    }
  });
});

// ---- Pixel type ------------------------------------------------------------------
// Titles are a raster serif in the manner of FK Raster Roman Compact Smooth: Tinos, an open
// Times design served by this site, is drawn at 13 px, every pixel is made fully on or off,
// and the bitmap is scaled up with its steps rounded off.
const FACES = {
  serif: 'Tinos, "Times New Roman", Times, "Liberation Serif", serif',
  sans: '"Geist", "Helvetica Neue", Helvetica, Arial, sans-serif',
};
const fontsReady = document.fonts && document.fonts.load
  ? Promise.all(['13px "Tinos"', '16px "Geist Pixel Line"', '16px "Geist Pixel Square"'].map(font => document.fonts.load(font))).catch(() => {})
  : Promise.resolve();
const pixelBlocks = new Set();
const wordBlocks = new Set();
const rgb = hex => { const n = parseInt(hex.slice(1), 16); return [n >> 16 & 255, n >> 8 & 255, n & 255]; };
function context(canvas) {
  try {
    return canvas.getContext("2d", {willReadFrequently: true});
  } catch {
    return null;
  }
}
function rasterise(value, face, size, color) {
  const canvas = document.createElement("canvas");
  const ctx = context(canvas);
  if (!ctx) return null;
  const font = `${size}px ${FACES[face] || FACES.serif}`;
  ctx.font = font;
  const metrics = ctx.measureText(value);
  const ascent = Math.ceil(metrics.fontBoundingBoxAscent || metrics.actualBoundingBoxAscent || size * 0.9);
  const descent = Math.ceil(metrics.fontBoundingBoxDescent || metrics.actualBoundingBoxDescent || size * 0.25);
  canvas.width = Math.max(1, Math.ceil(metrics.width) + 2);
  canvas.height = Math.max(1, ascent + descent);
  ctx.font = font;
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = "#000";
  ctx.fillText(value, 1, ascent);
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const [r, g, b] = rgb(color);
  const data = image.data;
  for (let i = 0; i < data.length; i += 4) {
    const on = data[i + 3] >= 100;
    data[i] = r;
    data[i + 1] = g;
    data[i + 2] = b;
    data[i + 3] = on ? 255 : 0;
  }
  ctx.putImageData(image, 0, 0);
  return canvas;
}
// Scales the bitmap to the screen's own pixels. Smooth rounds the pixel steps: a light
// blur, then every pixel is made fully on or off again.
function paintRow(row, density, smooth, color) {
  const {bits, view} = row;
  view.width = bits.width * density;
  view.height = bits.height * density;
  const ctx = context(view);
  if (!ctx) return;
  ctx.imageSmoothingEnabled = smooth;
  if (smooth && "filter" in ctx) ctx.filter = `blur(${(density * 0.3).toFixed(2)}px)`;
  ctx.drawImage(bits, 0, 0, view.width, view.height);
  if (!smooth) return;
  ctx.filter = "none";
  const image = ctx.getImageData(0, 0, view.width, view.height);
  const [r, g, b] = rgb(color);
  const data = image.data;
  for (let i = 0; i < data.length; i += 4) {
    const on = data[i + 3] >= 96;
    data[i] = r;
    data[i + 1] = g;
    data[i + 2] = b;
    data[i + 3] = on ? 255 : 0;
  }
  ctx.putImageData(image, 0, 0);
}
function pixelText(lines, {face = "serif", size = 13, color = "", max = 9, min = 2, align = "left", cls = "", label, hidden = false, smooth = true} = {}) {
  const specs = lines.map(line => typeof line === "string" ? {text: line} : line);
  // Titles in the ink colour are drawn dark and turned light by CSS in dark mode.
  const ink = !color;
  if (ink) color = "#1e1e1e";
  // A title that repeats a real heading is hidden from screen readers so it is not read twice.
  const block = el("div", {class: `px px-${align} px-wait ${ink ? "ink " : ""}${cls}`.trim(), role: "img", "aria-label": label || specs.map(spec => spec.text).join(" "),
    "aria-hidden": hidden ? "true" : null});
  const rows = specs.map(spec => {
    const slot = el("span", {class: "px-slot"});
    block.append(el("div", {class: "px-row"}, spec.before || null, slot, spec.after || null));
    return {spec, slot, bits: null, view: null, density: 0, extra: (spec.before ? 16 : 0) + (spec.after ? 16 : 0)};
  });
  block.pixel = {rows, max, min, color, smooth, ready: false, fitted: false};
  pixelBlocks.add(block);
  fontsReady.then(() => requestAnimationFrame(() => {
    if (!block.isConnected) {
      pixelBlocks.delete(block);
      return;
    }
    for (const row of rows) {
      row.bits = rasterise(row.spec.text, face, size, color);
      if (row.bits) {
        row.view = document.createElement("canvas");
        row.slot.append(row.view);
      } else {
        row.slot.append(el("span", {class: `px-fallback ${face}`}, row.spec.text));
      }
    }
    block.pixel.ready = true;
    fitPixels(block);
  }));
  return block;
}
function fitPixels(block) {
  if (!block.isConnected) {
    pixelBlocks.delete(block);
    return;
  }
  const p = block.pixel;
  if (!p.ready) return;
  const room = block.clientWidth;
  const widest = Math.max(1, ...p.rows.map(row => (row.bits ? row.bits.width : 0) + row.extra));
  const scale = Math.max(p.min, Math.min(p.max, room ? Math.floor(room / widest) : p.max));
  const density = Math.max(2, Math.min(24, Math.ceil(scale * (window.devicePixelRatio || 1))));
  block.style.setProperty("--px", `${scale}px`);
  for (const row of p.rows) {
    if (!row.bits) continue;
    if (row.density !== density) {
      paintRow(row, density, p.smooth, p.color);
      row.density = density;
    }
    row.view.style.width = `${row.bits.width * scale}px`;
    row.view.style.height = `${row.bits.height * scale}px`;
  }
  p.fitted = true;
  block.classList.remove("px-wait");
}
// A line of real text sized to fill its box, like the giant wordmark in the footer.
function fitWord(node) {
  if (!node.isConnected) {
    wordBlocks.delete(node);
    return;
  }
  node.style.fontSize = "100px";
  const width = node.firstChild.getBoundingClientRect().width;
  const room = node.clientWidth;
  if (width && room) node.style.fontSize = `${Math.max(24, Math.min(480, Math.floor(100 * room * 0.98 / width)))}px`;
  node.dataset.fitted = "1";
  node.classList.remove("px-wait");
}
function bigWord(value, cls) {
  const node = el("div", {class: `${cls} px-wait`, "aria-hidden": "true"}, el("span", {}, value));
  wordBlocks.add(node);
  fontsReady.then(() => requestAnimationFrame(() => fitWord(node)));
  return node;
}
let resizeTimer = 0;
addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    pixelBlocks.forEach(fitPixels);
    wordBlocks.forEach(fitWord);
  }, 120);
});

// ---- Motion: text that scrambles into place, a pixel trail, a pixel curtain ----
const GLYPHS = "!<>-_/[]{}=+*^?#ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function scramble(node) {
  if (reducedMotion() || node.dataset.scrambling || node.children.length) return;
  const final = node.textContent;
  node.dataset.scrambling = "1";
  let frame = 0;
  const frames = 10;
  const step = () => {
    frame += 1;
    if (!node.isConnected || frame >= frames) {
      node.textContent = final;
      delete node.dataset.scrambling;
      return;
    }
    const settled = Math.floor(final.length * frame / frames);
    node.textContent = Array.from(final, (char, index) => index < settled || char === " " ? char : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]).join("");
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
document.addEventListener("pointerover", event => {
  const target = event.target instanceof Element ? event.target.closest("[data-scramble]") : null;
  if (target && !(event.relatedTarget instanceof Node && target.contains(event.relatedTarget))) scramble(target);
});
function veil() {
  if (reducedMotion()) return () => {};
  const cols = 12;
  const rows = Math.max(1, Math.ceil(cols * innerHeight / Math.max(1, innerWidth)));
  const cover = el("div", {class: "veil", "aria-hidden": "true"});
  cover.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
  cover.style.gridTemplateRows = `repeat(${rows}, 1fr)`;
  for (let i = 0; i < cols * rows; i += 1) {
    const pixel = el("i");
    pixel.style.transitionDelay = `${Math.floor(Math.random() * 420)}ms`;
    cover.append(pixel);
  }
  const words = el("div", {class: "veil-text", "aria-hidden": "true"}, "Connecting");
  document.body.append(cover, words);
  return () => {
    requestAnimationFrame(() => {
      cover.classList.add("out");
      words.classList.add("out");
    });
    setTimeout(() => {
      cover.remove();
      words.remove();
    }, 900);
  };
}

async function api(path, body) {
  let reply;
  try {
    reply = await fetch(path, body ? {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)} : {});
  } catch {
    throw new Error("The site could not be reached. Check your connection and try again.");
  }
  const data = await reply.json().catch(() => ({}));
  if (!reply.ok) {
    const problem = data.error && typeof data.error === "object" ? data.error.message : data.error;
    throw new Error(problem || "Something went wrong. Try again.");
  }
  return data;
}

// ---- Formatting ------------------------------------------------------------
// Prices, balances and payments are all in USDT.
const COIN = "USDT";
function money(value) {
  const n = Number(value || 0);
  const digits = n !== 0 && Math.abs(n) < 0.01 ? 6 : 2;
  return `${n < 0 ? "-" : ""}${Math.abs(n).toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: digits})} ${COIN}`;
}
// Usage costs keep their precision: a request often costs a fraction of a cent.
function cost(value) {
  const n = Number(value || 0);
  return `${n.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 6})} ${COIN}`;
}
const figure = value => {
  const n = Number(value || 0);
  return n === 0 ? "0" : n.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 6});
};
const perMillion = value => `${figure(value)} ${COIN}`;
const count = value => Number(value || 0).toLocaleString("en-US");
const plural = (n, word, many = word + "s") => `${count(n)} ${n === 1 ? word : many}`;
const when = seconds => seconds ? new Date(seconds * 1000).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"}) : "";
function ago(seconds) {
  if (!seconds) return "Never";
  const gap = Math.max(0, Date.now() / 1000 - seconds);
  if (gap < 60) return "Just now";
  if (gap < 3600) return `${Math.floor(gap / 60)} min ago`;
  if (gap < 86400) return `${Math.floor(gap / 3600)} h ago`;
  if (gap < 86400 * 30) return `${Math.floor(gap / 86400)} d ago`;
  return new Date(seconds * 1000).toLocaleDateString(undefined, {dateStyle: "medium"});
}
const joinWords = words => words.length < 3 ? words.join(" and ") : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;

// Buyers see models by name and maker. Where a model runs is for the admin's eyes only.
const MAKERS = {openai: "OpenAI", anthropic: "Anthropic", google: "Google", meta: "Meta", qwen: "Qwen", deepseek: "DeepSeek",
  zai: "Z.ai", moonshot: "Moonshot AI", minimax: "MiniMax", mistral: "Mistral", microsoft: "Microsoft", xai: "xAI",
  nvidia: "NVIDIA", cohere: "Cohere", ibm: "IBM", allenai: "Ai2", nous: "Nous Research", huggingface: "Hugging Face",
  liquid: "Liquid AI", ai21: "AI21", baidu: "Baidu", tencent: "Tencent", bytedance: "ByteDance", stepfun: "StepFun",
  inclusionai: "inclusionAI", arcee: "Arcee AI", amazon: "Amazon", perplexity: "Perplexity", tii: "TII", bigcode: "BigCode"};
const makerName = key => known(MAKERS, key) ? MAKERS[key] : key ? key.charAt(0).toUpperCase() + key.slice(1) : "Other";
const TONES = {openai: "lime", anthropic: "orange", google: "blue"};
const toneOf = key => known(TONES, key) ? TONES[key] : "ink";
// The admin's connection table still names each source, so a missing key can be fixed.
const PROVIDERS = {openai: "OpenAI", anthropic: "Anthropic", google: "Google", ollama: "Ollama", kilo: "Kilo", opencode: "OpenCode"};
const providerName = p => known(PROVIDERS, p) ? PROVIDERS[p] : p ? p.charAt(0).toUpperCase() + p.slice(1) : "Other";
const WHERE = {paid: "Provider API", local: "Your GPU", free: "Gateway API", attached: "Started with yougori run"};
const BRIDGE = {paid: "Provider bridge", local: "Ollama", free: "Gateway bridge"};
const place = sandbox => known(WHERE, sandbox) ? WHERE[sandbox] : text(sandbox);
const RANK = {paid: 0, local: 1, attached: 1, free: 2};
const rank = sandbox => known(RANK, sandbox) ? RANK[sandbox] : 3;
const isFree = m => Number(m.priceIn) === 0 && Number(m.priceOut) === 0;
function shortId(m) {
  const id = text(m.name);
  return id.slice(id.lastIndexOf("/") + 1);
}

// ---- Building blocks ---------------------------------------------------------
function bubble(label, {onclick, type = "button", tone = "", size = "", disabled = false, title} = {}) {
  return el("button", {class: ["bubble", tone, size].filter(Boolean).join(" "), type, onclick, disabled, title},
    el("span", {class: "bubble-arrow", "aria-hidden": "true"}, pixelIcon("arrow")),
    el("span", {class: "bubble-label"}, label),
    el("span", {class: "bubble-arrow dup", "aria-hidden": "true"}, pixelIcon("arrow")));
}
function bracket(label, onclick, {tone = "", title, aria, current = false} = {}) {
  return el("button", {class: tone ? `bracket ${tone}` : "bracket", type: "button", onclick, title, "aria-label": aria,
    "aria-current": current ? "page" : null, "data-scramble": ""}, label);
}
function flat(label, {onclick, tone = "", type = "button", title, disabled = false} = {}) {
  return el("button", {class: tone ? `flat ${tone}` : "flat", type, onclick, title, disabled}, label);
}
const tag = (label, tone = "lime", title) => el("span", {class: `tag ${tone}`, title}, label);
const pair = (square, round, tone = "lime") => el("span", {class: `pair ${tone}`}, el("span", {class: "sq"}, square), el("span", {class: "rd"}, round));
const caption = (label, tone = "blue") => el("div", {class: "caption"}, el("span", {class: `dot ${tone}`}), el("span", {}, label));
function brackets(label) {
  const words = el("span", {class: "brackets-text"}, label);
  requestAnimationFrame(() => scramble(words));
  return el("div", {class: "brackets"}, el("span", {"aria-hidden": "true"}, "["), words, el("span", {"aria-hidden": "true"}, "]"));
}
function callout(tone, ...message) {
  return el("div", {class: `callout ${tone}`, role: tone === "red" ? "alert" : "status"}, el("span", {class: `dot ${tone}`}), el("div", {}, ...message));
}
function win(title, body, {tone = "", cls = "", action = null, foot = null, flush = false} = {}) {
  return el("div", {class: ["win", tone, cls].filter(Boolean).join(" ")},
    el("div", {class: "win-dots", "aria-hidden": "true"}, el("i"), el("i"), el("i")),
    el("div", {class: "win-bar"}, el("span", {class: "win-title"}, title), action || el("span", {class: "win-plus", "aria-hidden": "true"}, "[+]")),
    el("div", {class: flush ? "win-body flush" : "win-body"}, body),
    foot ? el("div", {class: "win-foot"}, foot) : null);
}
function emptyState(title, detail, action) {
  return el("div", {class: "empty"}, el("div", {class: "empty-mark", "aria-hidden": "true"}, pixelIcon("star")),
    el("h3", {}, title), el("p", {}, detail), action ? el("div", {class: "row center"}, action) : null);
}
function skeleton(lines = 4) {
  return el("div", {class: "loading", "aria-busy": "true", "aria-label": "Loading"},
    Array.from({length: lines}, (_, i) => el("div", {class: "bar", style: `width:${92 - i * 11}%`})));
}
function toast(message, bad = false) {
  let host = $(".toasts");
  if (!host) {
    host = el("div", {class: "toasts", "aria-live": "polite"});
    document.body.append(host);
  }
  const note = el("div", {class: bad ? "toast bad" : "toast", role: bad ? "alert" : "status"},
    el("div", {class: "toast-bar"}, el("span", {class: `dot ${bad ? "red" : "lime"}`}), el("span", {}, bad ? "Problem" : "Done")),
    el("div", {class: "toast-body"}, message));
  host.append(note);
  setTimeout(() => note.remove(), bad ? 6500 : 3400);
}
function copyBracket(source, label = "copy") {
  const node = bracket(label, async () => {
    try {
      await navigator.clipboard.writeText(typeof source === "function" ? source() : source);
      node.textContent = "copied";
      setTimeout(() => { node.textContent = label; }, 1400);
    } catch {
      toast("This browser blocked copying. Select the text and copy it instead.", true);
    }
  });
  node.classList.add("copy");
  return node;
}
const secretBox = value => el("div", {class: "secret"}, el("code", {}, value), copyBracket(value));
function confirmDialog(title, detail, confirmLabel = "Confirm", danger = false) {
  return new Promise(resolve => {
    let settled = false;
    const dialog = el("dialog", {"aria-labelledby": "dialog-title"});
    const finish = answer => {
      if (settled) return;
      settled = true;
      dialog.close();
      dialog.remove();
      resolve(answer);
    };
    dialog.append(win(danger ? "Careful" : "Confirm", [
      el("h2", {class: "dialog-title", id: "dialog-title"}, title),
      el("p", {class: "dialog-text"}, detail),
      el("div", {class: "row end dialog-actions"}, bracket("Cancel", () => finish(false)),
        bubble(confirmLabel, {onclick: () => finish(true), tone: danger ? "danger" : ""}))]));
    dialog.addEventListener("cancel", event => { event.preventDefault(); finish(false); });
    document.body.append(dialog);
    dialog.showModal();
  });
}
// Like confirmDialog, with one text field. Resolves to the text (possibly empty), or null when cancelled.
function inputDialog(title, detail, {label, placeholder = "", help = "", confirmLabel = "Confirm"} = {}) {
  return new Promise(resolve => {
    let settled = false;
    const dialog = el("dialog", {"aria-labelledby": "dialog-title"});
    const input = el("input", {class: "input mono", id: "dialog-input", placeholder, autocomplete: "off", spellcheck: "false"});
    const finish = answer => {
      if (settled) return;
      settled = true;
      dialog.close();
      dialog.remove();
      resolve(answer);
    };
    dialog.append(win("Confirm", [
      el("h2", {class: "dialog-title", id: "dialog-title"}, title),
      el("p", {class: "dialog-text"}, detail),
      el("div", {class: "dialog-field"}, field(label, input, help)),
      el("div", {class: "row end dialog-actions"}, bracket("Cancel", () => finish(null)),
        bubble(confirmLabel, {onclick: () => finish(input.value.trim())}))]));
    dialog.addEventListener("cancel", event => { event.preventDefault(); finish(null); });
    document.body.append(dialog);
    dialog.showModal();
    input.focus();
  });
}
function field(label, control, help) {
  return el("div", {class: "field"}, el("label", {class: "label", for: control.id || null}, label), control, help ? el("span", {class: "help"}, help) : null);
}
function pageHead(title, label, detail, ...actions) {
  actions = actions.filter(Boolean);
  return el("header", {class: "page-head"},
    el("div", {class: "page-head-top"}, caption(label), actions.length ? el("div", {class: "row"}, actions) : null),
    el("h1", {class: "sr-only"}, title),
    pixelText([title], {size: 13, max: 8, cls: "rgb page-title", hidden: true}),
    detail ? el("p", {class: "statement s"}, detail) : null);
}
const sectionHead = (label, statement) => el("div", {class: "section-head"}, caption(label), statement ? el("p", {class: "statement s"}, statement) : null);
const stat = (label, value, hint) => el("div", {class: "stat"}, caption(label, "lime"),
  el("div", {class: "stat-value"}, value), hint ? el("div", {class: "stat-hint"}, hint) : null);
function toggles(options, selected, onchange, label, tone = "") {
  const group = el("div", {class: "toggles", role: "group", "aria-label": label});
  for (const [id, name] of options) {
    group.append(el("button", {class: tone ? `toggle ${tone}` : "toggle", type: "button", "aria-pressed": String(id === selected), onclick: event => {
      group.querySelectorAll("button").forEach(item => item.setAttribute("aria-pressed", String(item === event.currentTarget)));
      onchange(id);
    }}, name));
  }
  return group;
}
function codeWindow(initial) {
  let snippets = initial;
  let chosen = Object.keys(snippets)[0];
  const pre = el("pre", {tabindex: "0"});
  const show = () => pre.replaceChildren(snippets[chosen]);
  const tabs = toggles(Object.keys(snippets).map(name => [name, name]), chosen, id => { chosen = id; show(); }, "Language");
  const node = win("Quickstart", [
    el("div", {class: "addr-row"}, el("span", {class: "lights", "aria-hidden": "true"}, el("i"), el("i"), el("i")),
      el("span", {class: "addr"}, pixelIcon("globe"), el("span", {}, `${location.origin}/v1/chat/completions`), pixelIcon("refresh"))),
    el("div", {class: "code-tabs"}, tabs, el("span", {class: "spacer"}), copyBracket(() => snippets[chosen], "copy code")),
    pre], {tone: "night", cls: "code", flush: true});
  node.update = next => {
    snippets = next;
    show();
  };
  show();
  return node;
}
function samples(model, key) {
  model = model || "MODEL_ID";
  key = key || "YOUR_API_KEY";
  const base = location.origin;
  return {
    cURL: `curl ${base}/v1/chat/completions \\\n  -H "Authorization: Bearer ${key}" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "model": "${model}",\n    "messages": [{"role": "user", "content": "Hello"}]\n  }'`,
    Python: `from openai import OpenAI\n\nclient = OpenAI(base_url="${base}/v1", api_key="${key}")\n\nreply = client.chat.completions.create(\n    model="${model}",\n    messages=[{"role": "user", "content": "Hello"}],\n)\nprint(reply.choices[0].message.content)`,
    JavaScript: `import OpenAI from "openai";\n\nconst client = new OpenAI({ baseURL: "${base}/v1", apiKey: "${key}" });\n\nconst reply = await client.chat.completions.create({\n  model: "${model}",\n  messages: [{ role: "user", content: "Hello" }],\n});\nconsole.log(reply.choices[0].message.content);`,
  };
}

// ---- App state, navigation and page addresses -----------------------------------
const PATHS = {models: "/", keys: "/keys", admin: "/admin", signin: "/signin", signup: "/signup"};
const TITLES = {models: "Models", keys: "API keys", admin: "Admin", signin: "Sign in", signup: "Create account"};
let me = {signedIn: false};
let current = "models";
let returnTo = "";

function routeFromLocation() {
  const hash = location.hash.slice(1);
  const path = location.pathname.replace(/\/+$/, "") || "/";
  // Credits now live on the API keys page; old /credits links land there.
  if (hash === "credits" || path === "/credits") return "keys";
  if (known(PATHS, hash)) return hash;  // Addresses from the earlier site used #keys.
  return Object.keys(PATHS).find(id => PATHS[id] === path) || "models";
}
async function loadMe() {
  try {
    me = await api("/api/me");
  } catch (error) {
    me = {signedIn: false};
    toast(error.message, true);
  }
}
async function refresh() {
  await loadMe();
  draw();
}
// Keeps the balance current while API calls spend it in the background.
async function syncMe() {
  try {
    const fresh = await api("/api/me");
    const changed = fresh.signedIn !== me.signedIn || Boolean(fresh.admin) !== Boolean(me.admin);
    me = fresh;
    if (changed) draw();
    else paintChrome();
  } catch {
    // The page already shows what it has; the next action reports any problem.
  }
}
function go(id, replace = false) {
  const next = known(PATHS, id) ? id : "models";
  const moved = next !== current;
  current = next;
  if (location.pathname !== PATHS[next] || location.hash) history[replace ? "replaceState" : "pushState"](null, "", PATHS[next]);
  draw();
  if (moved) window.scrollTo(0, 0);
  if (!replace && me.signedIn) syncMe();
}
function needSignin(id) {
  returnTo = id;
  go("signin", true);
}
async function signout() {
  try {
    await api("/api/signout", {});
  } catch (error) {
    toast(error.message, true);
  }
  await loadMe();
  go("models");
  toast("Signed out.");
}
function pagesFor() {
  const pages = [["models", "Models"]];
  if (me.signedIn) pages.push(["keys", "API keys"]);
  if (me.admin) pages.push(["admin", "Admin"]);
  return pages;
}

function paintChrome() {
  const name = me.siteName || "My API";
  const toggle = el("button", {class: "nav-toggle", type: "button", "aria-label": "Menu", "aria-expanded": "false", "aria-controls": "nav-panel"}, el("i"), el("i"));
  const panel = el("div", {class: "nav-panel", id: "nav-panel", inert: true}, el("div", {},
    el("ul", {class: "nav-links"}, pagesFor().map(([id, label]) => el("li", {},
      el("button", {class: "nav-link", type: "button", "aria-current": id === current ? "page" : null, "data-scramble": "", onclick: () => go(id)}, label)))),
    el("ul", {class: "nav-small"}, me.signedIn
      ? [el("li", {class: "nav-email"}, me.email), el("li", {}, bracket(`balance ${money(me.credits)}`, () => go("keys"))), el("li", {}, bracket("sign out", signout))]
      : [el("li", {}, bracket("sign in", () => go("signin"))), el("li", {}, bracket("create account", () => go("signup")))],
      el("li", {}, themeSwitch()))));
  const bar = el("nav", {class: "nav", "aria-label": "Site"}, el("div", {class: "nav-bar"},
    el("div", {class: "nav-top"},
      el("button", {class: "nav-brand", type: "button", onclick: () => go("models")},
        el("span", {class: "mark", "aria-hidden": "true"}, pixelIcon("plus")), el("span", {class: "nav-name"}, name)),
      el("span", {class: "nav-where"}, `[${TITLES[current]}]`),
      me.admin && current !== "admin" ? el("span", {class: "nav-admin"}, bracket("admin", () => go("admin"), {aria: "Open Admin"})) : null,
      toggle),
    panel));
  toggle.addEventListener("click", () => {
    const open = bar.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
    if (open) panel.removeAttribute("inert");
    else panel.setAttribute("inert", "");
  });
  const quick = el("div", {class: "quick"},
    pagesFor().map(([id, label]) => bracket(label, () => go(id), {current: id === current})),
    themeSwitch(),
    me.signedIn
      ? [el("button", {class: "pair lime balance", type: "button", title: "Your balance", onclick: () => go("keys")}, el("span", {class: "sq"}, "Balance"), el("span", {class: "rd"}, money(me.credits))),
         bracket("sign out", signout, {aria: "Sign out"})]
      : [bracket("sign in", () => go("signin")), bubble("Get started", {size: "small", onclick: () => go("signup")})]);
  $("#top").replaceChildren(bar, quick);
}
document.addEventListener("keydown", event => {
  if (event.key !== "Escape") return;
  const open = $(".nav.open");
  if (open) {
    open.classList.remove("open");
    open.querySelector(".nav-toggle")?.setAttribute("aria-expanded", "false");
    open.querySelector(".nav-panel")?.setAttribute("inert", "");
  }
});
function footer() {
  const name = me.siteName || "My API";
  const links = pagesFor();
  if (!me.signedIn) links.push(["signin", "Sign in"], ["signup", "Create account"]);
  $("#foot").replaceChildren(el("div", {class: "foot-inner"},
    el("div", {class: "foot-wins"},
      win("Website", el("div", {class: "foot-links"}, links.map(([id, label]) => bracket(label, () => go(id)))), {tone: "lime"}),
      win("API", el("div", {class: "foot-links mono"}, el("span", {}, "GET /v1/models"), el("span", {}, "POST /v1/chat/completions")))),
    el("div", {class: "foot-about"},
      el("div", {}, el("div", {}, "OpenAI-compatible API"), el("div", {class: "dim"}, "Pay per token, from a prepaid balance")),
      el("div", {class: "right"}, el("div", {}, name), el("div", {class: "dim"}, `Prices in ${COIN} per million tokens`))),
    // The giant word sits on the bottom edge with its lower half cut off, as in the reference.
    bigWord(name, "foot-mark")));
}

let stopPage = () => {};
function draw() {
  stopPage();
  stopPage = () => {};
  for (const block of pixelBlocks) if (block.pixel.fitted && !block.isConnected) pixelBlocks.delete(block);
  for (const node of wordBlocks) if (node.dataset.fitted && !node.isConnected) wordBlocks.delete(node);
  paintChrome();
  document.title = `${TITLES[current]} · ${me.siteName || "My API"}`;
  const view = $("#view");
  view.replaceChildren();
  view.classList.remove("view-in");
  void view.offsetWidth;
  view.classList.add("view-in");
  const pages = {models: drawModels, keys: drawKeys, admin: drawAdmin,
    signin: target => drawAuth(target, false), signup: target => drawAuth(target, true)};
  const fail = error => {
    console.error(error);
    view.append(el("div", {class: "section"}, callout("red", "This page could not finish loading. Reload the page to try again.")));
  };
  try {
    const pending = pages[current](view);
    if (pending && typeof pending.catch === "function") pending.catch(fail);
  } catch (error) {
    fail(error);
  }
  footer();
}

// ---- Models --------------------------------------------------------------------
async function drawModels(view) {
  let filter = "all";
  let sort = "featured";
  let models = [];
  let stopped = false;
  let timer;
  let previous = "";
  stopPage = () => { stopped = true; clearTimeout(timer); };
  const sync = el("p", {class: "note", "aria-live": "polite"}, "Discovering models automatically…");
  const list = el("div", {class: "mlist"}, skeleton(5));
  const total = el("span", {class: "count", "aria-live": "polite"});
  const search = el("input", {type: "search", placeholder: "Search models", "aria-label": "Search models", autocomplete: "off", spellcheck: "false"});
  search.addEventListener("input", () => render());
  // The filters are the makers on offer: buyers pick models by who made them.
  const makerFilters = makers => toggles([["all", "All"], ...makers.map(key => [key, makerName(key)])], filter,
    id => { filter = id; render(); }, "Filter models by maker");
  let filters = makerFilters([]);
  const order = el("select", {class: "select", "aria-label": "Sort models", onchange: event => { sort = event.target.value; render(); }},
    el("option", {value: "featured"}, "Featured"), el("option", {value: "low"}, "Price: low to high"),
    el("option", {value: "high"}, "Price: high to low"), el("option", {value: "name"}, "Name"));
  const toolbar = el("div", {class: "toolbar"}, el("label", {class: "address grow"}, pixelIcon("search"), search, el("kbd", {}, "/")), filters, total, order);
  const lede = el("p", {class: "hero-lede"}, "Leading models behind one key and one prepaid balance. Point any OpenAI SDK at this site and keep your code.");
  const fact = (label, value, tone) => el("span", {class: `pair ${tone} fact`}, el("span", {class: "sq"}, value), el("span", {class: "rd"}, label));
  const facts = el("div", {class: "hero-facts"}, fact("Models ready", "…", "lime"), fact("Makers", "…", "blue"));
  const code = codeWindow(samples());
  const cards = el("div", {class: "cards"});
  const makerSection = el("section", {class: "section", hidden: true}, sectionHead("Makers", "The labs behind the models."), cards);
  const createKey = () => {
    if (me.signedIn) return go("keys");
    returnTo = "keys";
    go("signup");
  };

  // The models are the hero: one small title line, then the list straight away.
  if (!me.signedIn && !me.anyAdmin) {
    view.append(el("div", {class: "notice"}, callout("amber", "Admin setup is not finished. Create the admin account in the Yougori CLI, then sign in here.")));
  }
  view.append(el("section", {class: "hero"},
    el("div", {class: "hero-row"}, el("h1", {class: "hero-title"}, el("span", {class: "dot"}), "One API for every model"), eye()),
    el("div", {class: "hero-row"}, lede, el("div", {class: "hero-cta"}, facts,
      bubble("Create API key", {size: "small", onclick: createKey}),
      me.signedIn ? null : bracket("Sign in", () => go("signin")))),
    sync, toolbar, list,
    el("p", {class: "note"}, `Prices are in ${COIN} per million tokens, charged from your prepaid balance after each request.`)));
  if (!me.signedIn) {
    view.append(
      el("section", {class: "section"}, sectionHead("Quickstart", "Point any OpenAI SDK at this address and keep your code."), code),
      makerSection,
      el("section", {class: "night bleed"}, el("div", {class: "night-inner"},
        el("p", {class: "night-text"}, "Every request is paid from a prepaid balance, at the prices on this page. Keys are shown once and kept only as fingerprints. Nothing here loads from anywhere else."),
        el("div", {class: "night-about"},
          el("div", {}, el("div", {}, "Keys shown once"), el("div", {class: "dim"}, "Kept as fingerprints")),
          el("div", {class: "right"}, el("div", {}, "Pay per token"), el("div", {class: "dim"}, "From prepaid credits"))))));
  }

  await refresh();

  async function refresh() {
    try {
      const data = await api("/api/models");
      if (stopped) return;
      sync.textContent = data.updatedAt
        ? `Models update automatically every ${data.refreshSeconds || 30} seconds. Last checked ${new Date(data.updatedAt * 1000).toLocaleTimeString()}.`
        : "Discovering models automatically. They appear here as soon as they are ready.";
      const signature = JSON.stringify(data.models);
      if (signature !== previous) {
        previous = signature;
        models = data.models || [];
        update();
      }
    } catch (error) {
      if (stopped) return;
      sync.textContent = "Reconnecting to model discovery…";
      if (!previous) list.replaceChildren(callout("red", error.message));
    } finally {
      if (!stopped) timer = setTimeout(refresh, 5000);
    }
  }

  function update() {
  const ready = models.filter(m => m.available);
  const byMaker = new Map();
  for (const m of models.filter(m => m.available || (me.admin && m.discovered))) {
    byMaker.set(m.maker || "", [...(byMaker.get(m.maker || "") || []), m]);
  }
  // Most models first; models whose maker is unknown are listed but get no filter.
  const makers = [...byMaker].filter(([key]) => key)
    .sort((a, b) => b[1].length - a[1].length || makerName(a[0]).localeCompare(makerName(b[0]))).map(([key]) => key);
  const shown = makers.slice(0, 6);
  if (filter !== "all" && !shown.includes(filter)) {
    if (makers.includes(filter)) shown.push(filter);
    else filter = "all";
  }
  const next = makerFilters(shown);
  filters.replaceWith(next);
  filters = next;
  const named = makers.filter(key => byMaker.get(key).some(m => m.available)).map(makerName);
  if (named.length) {
    const lead = named.length > 4 ? `${named.slice(0, 3).join(", ")} and ${named.length - 3} more makers` : joinWords(named);
    lede.textContent = `Models from ${lead}, behind one key and one prepaid balance. Point any OpenAI SDK at this site and keep your code.`;
  } else if (ready.length) {
    lede.textContent = "Leading models behind one key and one prepaid balance. Point any OpenAI SDK at this site and keep your code.";
  } else {
    lede.textContent = "Models appear here automatically as soon as they are ready. Every one is served through this API.";
  }
  facts.replaceChildren(fact("Models ready", count(ready.length), "lime"), fact("Makers", count(named.length), "blue"));
  const example = ready.find(m => ["openai", "anthropic", "google"].includes(m.maker)) || ready[0];
  code.update(samples(example && example.name));
  const groups = [...byMaker].map(([key, group]) => [key, group.filter(m => m.available)]).filter(([, group]) => group.length)
    .sort((a, b) => b[1].length - a[1].length || makerName(a[0]).localeCompare(makerName(b[0])));
  makerSection.hidden = !groups.length;
  if (groups.length) cards.replaceChildren(...groups.map(([key, group]) => makerCard(key, group)));
  render();
  }

  function render() {
    const query = search.value.trim().toLowerCase();
    const both = m => Number(m.priceIn) + Number(m.priceOut);
    const orders = {
      featured: (a, b) => (b.available - a.available) || rank(a.sandbox) - rank(b.sandbox)
        || makerName(a.maker).localeCompare(makerName(b.maker)) || both(b) - both(a) || shortId(a).localeCompare(shortId(b)),
      low: (a, b) => both(a) - both(b) || shortId(a).localeCompare(shortId(b)),
      high: (a, b) => both(b) - both(a) || shortId(a).localeCompare(shortId(b)),
      name: (a, b) => shortId(a).localeCompare(shortId(b)),
    };
    const rows = models
      .filter(m => m.available || (me.admin && m.discovered))
      .filter(m => filter === "all" || m.maker === filter)
      .filter(m => !query || `${m.name} ${makerName(m.maker)}`.toLowerCase().includes(query))
      .sort(orders[sort]);
    total.textContent = plural(rows.length, "model");
    if (!rows.length) {
      const anything = models.some(m => m.available || (me.admin && m.discovered));
      list.replaceChildren(anything
        ? emptyState("No models match", "Try another word, or show all models.")
        : emptyState("No models are ready yet",
            me.admin ? "Discovery runs automatically. Add provider API keys in the CLI setup or pull a local model." : "New models are on their way. This list updates automatically.",
            me.admin ? bubble("Open Admin", {size: "small", onclick: () => go("admin")}) : null));
      return;
    }
    list.replaceChildren(...rows.map(modelRow));
  }

}
document.addEventListener("keydown", event => {
  if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
  const active = document.activeElement;
  if (active && (/^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName) || active.isContentEditable)) return;
  const box = $(".toolbar .address input");
  if (box) {
    event.preventDefault();
    box.focus();
  }
});
function modelRow(m, index) {
  // "Free" only when the admin has set both prices to 0.
  const free = isFree(m);
  const status = !m.available ? tag("Needs a price", "orange") : free ? tag("Free", "lime round") : null;
  const price = !m.available
    ? el("div", {class: "whole"}, el("span", {}, "Set a price in Admin"))
    : free ? el("div", {class: "whole"}, el("b", {}, "Free"), el("span", {}, "No charge per token"))
    : [el("div", {}, el("b", {}, figure(m.priceIn)), el("span", {}, `${COIN} /1M input`)),
       el("div", {}, el("b", {}, figure(m.priceOut)), el("span", {}, `${COIN} /1M output`))];
  const name = shortId(m);
  return el("article", {class: m.available ? "mcard" : "mcard off"},
    el("div", {class: "mcard-top"}, el("span", {class: "mcard-index", "aria-hidden": "true"}, `[${String(index + 1).padStart(2, "0")}]`), status),
    el("div", {class: "mcard-tags"}, tag(makerName(m.maker), toneOf(m.maker))),
    el("div", {}, el("div", {class: "mcard-name"}, name), name === m.name ? null : el("div", {class: "mcard-id"}, m.name)),
    el("div", {class: "mcard-price"}, price),
    el("div", {class: "mcard-foot"}, copyBracket(m.name, "copy id")));
}
function makerCard(maker, group) {
  const tone = toneOf(maker);
  const paid = group.filter(m => !isFree(m)).sort((a, b) => Number(a.priceIn) - Number(b.priceIn));
  const colour = {lime: "#bcf015", orange: "#ff4c24", blue: "#7b5cff", ink: "#ebedf5", paper: "#ebedf5"}[tone];
  const pixels = el("div", {class: "pcard-pixels", "aria-hidden": "true"});
  for (let i = 0; i < 48; i += 1) {
    const pixel = el("i");
    pixel.style.setProperty("--d", `${Math.floor(Math.random() * 360)}ms`);
    pixels.append(pixel);
  }
  const name = makerName(maker);
  return el("article", {class: `pcard ${tone}`},
    el("div", {}, pair(name, plural(group.length, "model"), tone === "ink" ? "paper" : tone)),
    pixelText([name.slice(0, 2)], {size: 13, color: colour, max: 12, align: "center", hidden: true}),
    el("div", {class: "pcard-foot"},
      pixelText([name], {size: 13, color: "#f0f0f0", max: 3}),
      el("div", {class: "pcard-price"}, paid.length ? `From ${perMillion(paid[0].priceIn)} /1M input` : "Free")),
    pixels);
}

// ---- Sign in and sign up ------------------------------------------------------------
function drawAuth(view, isSignup) {
  if (me.signedIn) return go(returnTo || "models", true);
  const email = el("input", {class: "input", id: "email", type: "email", autocomplete: "username", placeholder: "you@example.com", required: true});
  const password = el("input", {class: "input", id: "password", type: "password", required: true,
    autocomplete: isSignup ? "new-password" : "current-password", minlength: isSignup ? "10" : null,
    placeholder: isSignup ? "At least 10 characters" : "Your password"});
  if (isSignup && !me.anyAdmin) {
    view.append(emptyState("Account setup is not finished", "The site owner creates the admin account in the Yougori CLI. Then you can sign up here."));
    return;
  }
  const problem = el("div");
  const submit = bubble(isSignup ? "Create account" : "Sign in", {type: "submit"});
  const form = el("form", {class: "auth-form", onsubmit: async event => {
    event.preventDefault();
    problem.replaceChildren();
    submit.disabled = true;
    try {
      const payload = {email: email.value.trim(), password: password.value};
      const result = await api(isSignup ? "/api/signup" : "/api/signin", payload);
      await loadMe();
      const next = result.admin && !me.walletSet ? "admin" : (returnTo || "models");
      returnTo = "";
      go(next, true);
      toast(isSignup ? "Your account is ready." : "Signed in.");
    } catch (error) {
      problem.replaceChildren(el("div", {class: "field"}, callout("red", error.message)));
      submit.disabled = false;
    }
  }},
    field("Email", email),
    field("Password", password),
    problem, submit);
  view.append(el("div", {class: "auth"},
    brackets(isSignup ? "Access: an email and a password" : "Access: members only"),
    el("h1", {class: "sr-only"}, isSignup ? "Create your account" : "Welcome back"),
    pixelText([isSignup ? "Create account" : "Welcome back"], {size: 13, max: 7, align: "center", cls: "rgb", hidden: true}),
    win(isSignup ? "New account" : "Sign in", form),
    el("div", {class: "switch"}, isSignup ? "Already have an account? " : "New here? ",
      el("button", {class: "link", type: "button", onclick: () => go(isSignup ? "signin" : "signup", true)}, isSignup ? "Sign in" : "Create an account"))));
  setTimeout(() => email.focus(), 0);
}

// ---- API keys, balance and payments -----------------------------------------------------
async function drawKeys(view) {
  if (!me.signedIn) return needSignin("keys");
  let example = "";
  let stopped = false;
  let timer;
  let waiting = new Set();
  let loading = false;
  let again = false;
  stopPage = () => { stopped = true; clearTimeout(timer); };
  const reveal = el("div");
  const table = el("div", {}, skeleton(3));
  const quick = codeWindow(samples());
  const stats = el("div", {class: "stats"}, stat("Balance", money(me.credits), "Available to spend"));
  const buy = el("div", {}, skeleton(4));
  const payments = el("div", {}, skeleton(2));
  const usage = el("div", {}, skeleton(3));
  const name = el("input", {class: "input", id: "key-name", placeholder: "For example: Production server", maxlength: "60", autocomplete: "off"});
  const model = el("select", {class: "select wide", id: "key-model"}, el("option", {value: ""}, "Every available model"));
  const create = bubble("Create key", {type: "submit"});
  const form = el("form", {onsubmit: async event => {
    event.preventDefault();
    create.disabled = true;
    try {
      const {key} = await api("/api/keys", {name: name.value.trim() || "Key", model: model.value || null});
      reveal.replaceChildren(el("section", {class: "section"}, win("Your new key", el("div", {class: "stack"},
        callout("amber", "Copy it now. Only a fingerprint is stored, so this key cannot be shown again."),
        secretBox(key)), {tone: "lime"})));
      quick.update(samples(model.value || example, key));
      name.value = "";
      toast("Key created.");
      list();
    } catch (error) {
      toast(error.message, true);
    }
    create.disabled = false;
  }},
    el("div", {class: "grid2 tight"}, field("Name", name), field("Allowed model", model, "Limit a key to one model to control what it can spend on.")),
    create);
  view.append(pageHead("API keys", "Your keys", `Keys let your apps call the API. Every request is paid from your ${COIN} balance, topped up on this page.`),
    stats,
    el("div", {class: "section grid2"},
      win("New key", form, {foot: [pixelIcon("star"), el("span", {}, "Send a key as a bearer token. Revoke it here the moment it leaks.")]}),
      win(`Add ${COIN}`, buy)),
    reveal,
    el("section", {class: "section"}, sectionHead("Keys"), win("Your keys", table, {flush: true})),
    el("section", {class: "section"}, sectionHead("Payments", "Your balance goes up by itself once the site owner confirms a payment."), win("Payments", payments, {flush: true})),
    el("section", {class: "section"}, sectionHead("Recent usage"), win("Usage", usage, {flush: true})),
    el("section", {class: "section"}, sectionHead("Quickstart", "Works with any OpenAI-compatible SDK."), quick));

  api("/api/models").then(({models}) => {
    const ready = (models || []).filter(m => m.available);
    for (const m of ready) model.append(el("option", {value: m.name}, m.name));
    const first = ready.find(m => ["openai", "anthropic", "google"].includes(m.maker)) || ready[0];
    example = first ? first.name : "";
    quick.update(samples(example));
  }).catch(() => {});

  async function list() {
    try {
      const {keys} = await api("/api/keys");
      if (!keys.length) {
        table.replaceChildren(emptyState("No keys yet", "Create one above to start calling the API."));
        return;
      }
      table.replaceChildren(el("div", {class: "table-wrap"}, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Key"), el("th", {}, "Allowed model"),
          el("th", {}, "Created"), el("th", {}, "Last used"), el("th", {}, "Status"), el("th", {class: "right"}, el("span", {class: "sr-only"}, "Actions")))),
        el("tbody", {}, keys.map(k => el("tr", {},
          el("td", {}, k.name),
          el("td", {}, el("span", {class: "mono"}, `${k.prefix}…`)),
          el("td", {}, k.model ? el("span", {class: "mono"}, k.model) : el("span", {class: "muted"}, "Any")),
          el("td", {class: "muted"}, ago(k.created_at)),
          el("td", {class: "muted"}, ago(k.last_used_at)),
          el("td", {}, k.exhausted_note ? tag("Quota reached", "amber", k.exhausted_note) : tag("Active")),
          el("td", {class: "right"}, flat("Revoke", {tone: "danger", onclick: async () => {
            const sure = await confirmDialog("Revoke this key?", `Apps using “${k.name}” stop working at once. This cannot be undone.`, "Revoke key", true);
            if (!sure) return;
            try {
              await api("/api/keys/delete", {id: k.id});
              toast("Key revoked.");
              list();
            } catch (error) {
              toast(error.message, true);
            }
          }}))))))));
    } catch (error) {
      table.replaceChildren(el("div", {class: "loading"}, callout("red", error.message)));
    }
  }

  // The balance, recent spending and usage. Drawn again when a payment lands.
  async function account() {
    try {
      const [fresh, {usage: rows}] = await Promise.all([api("/api/me"), api("/api/usage")]);
      if (stopped) return;
      if (fresh.signedIn) {
        me = fresh;
        paintChrome();
      }
      const spent = rows.reduce((sum, row) => sum + Number(row.cost || 0), 0);
      const tokens = rows.reduce((sum, row) => sum + Number(row.tokensIn || 0) + Number(row.tokensOut || 0), 0);
      stats.replaceChildren(stat("Balance", money(me.credits), "Available to spend"),
        stat("Spent recently", cost(spent), rows.length ? `Across your last ${plural(rows.length, "request")}` : "No requests yet"),
        stat("Tokens recently", count(tokens), "Input and output"));
      usage.replaceChildren(rows.length ? el("div", {class: "table-wrap"}, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Model"), el("th", {}, "When"), el("th", {class: "right"}, "Input tokens"),
          el("th", {class: "right"}, "Output tokens"), el("th", {class: "right"}, "Cost"))),
        el("tbody", {}, rows.map(row => el("tr", {},
          el("td", {}, el("span", {class: "mono"}, row.model)), el("td", {class: "muted", title: when(row.at)}, ago(row.at)),
          el("td", {class: "right num"}, count(row.tokensIn)), el("td", {class: "right num"}, count(row.tokensOut)),
          el("td", {class: "right num"}, cost(row.cost)))))))
        : emptyState("No usage yet", "Your requests and what each one cost appear here."));
    } catch (error) {
      if (!stopped) usage.replaceChildren(el("div", {class: "loading"}, callout("red", error.message)));
    }
  }

  // Waiting payments are checked every few seconds, so a confirmed one appears here by itself.
  async function listPayments() {
    if (loading) {
      again = true;
      return;
    }
    loading = true;
    clearTimeout(timer);
    try {
      const {payments: rows} = await api("/api/payments");
      if (stopped) return;
      const arrived = rows.filter(p => p.state === "paid" && waiting.has(p.reference));
      waiting = new Set(rows.filter(p => p.state === "waiting").map(p => p.reference));
      payments.replaceChildren(rows.length ? el("div", {class: "table-wrap"}, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Reference"), el("th", {class: "right"}, "Amount"), el("th", {}, "Status"),
          el("th", {class: "right"}, el("span", {class: "sr-only"}, "Actions")))),
        el("tbody", {}, rows.map(p => el("tr", {},
          el("td", {}, el("span", {class: "mono"}, p.reference), el("div", {class: "muted small"}, `${p.label || p.network} · ${when(p.created_at)}`)),
          el("td", {class: "right num"}, money(p.dollars)),
          el("td", {}, paymentState(p)),
          el("td", {class: "right"}, p.state === "waiting" ? flat("Cancel", {onclick: () => cancelPayment(p)}) : null))))))
        : emptyState("No payments yet", `Add ${COIN} above to top up your balance.`));
      if (arrived.length) {
        toast(`Payment received. ${money(arrived.reduce((sum, p) => sum + Number(p.dollars || 0), 0))} added to your balance.`);
        account();
      }
    } catch (error) {
      if (!stopped) payments.replaceChildren(el("div", {class: "loading"}, callout("red", error.message)));
    } finally {
      loading = false;
      if (!stopped && again) {
        again = false;
        listPayments();
      } else if (!stopped && waiting.size) {
        timer = setTimeout(listPayments, 5000);
      }
    }
  }

  async function cancelPayment(p) {
    const sure = await confirmDialog("Cancel this payment request?",
      `Only cancel if you have not sent the ${money(p.dollars)}. If you already sent it, keep the request so the site owner can match it.`, "Cancel request", true);
    if (!sure) return;
    try {
      await api("/api/payments/cancel", {reference: p.reference});
      toast("Payment request cancelled.");
      listPayments();
    } catch (error) {
      toast(error.message, true);
    }
  }

  // Balance is bought by sending USDT straight to the site owner's wallet.
  async function topUp() {
    let wallet;
    try {
      wallet = await api("/api/wallet");
    } catch (error) {
      buy.replaceChildren(callout("red", error.message));
      return;
    }
    if (stopped) return;
    if (!wallet.set) {
      buy.replaceChildren(callout("amber", "The site owner has not set up payments yet. Check back soon."));
      return;
    }
    const amount = el("input", {class: "input num", id: "amount", type: "number", min: "1", max: "10000", step: "0.01", value: "25", inputmode: "decimal"});
    const label = value => `${value} ${COIN}`;
    const presets = toggles([10, 25, 50, 100].map(value => [String(value), label(value)]), "25", value => { amount.value = value; }, "Amount", "lime");
    amount.addEventListener("input", () => presets.querySelectorAll(".toggle").forEach(item => item.setAttribute("aria-pressed", String(item.textContent === label(amount.value)))));
    const details = el("div");
    const ask = bubble("Get payment details", {onclick: async () => {
      const value = Number(amount.value);
      if (!(value >= 1 && value <= 10000) || Math.abs(Math.round(value * 100) - value * 100) > 1e-6) {
        toast(`Choose an amount from 1 to 10,000 ${COIN}, in whole cents.`, true);
        return;
      }
      ask.disabled = true;
      try {
        const result = await api("/api/credits/buy", {dollars: value});
        details.replaceChildren(el("div", {class: "stack", style: "margin-top:18px"},
          callout("blue", result.instruction),
          field(`Send to this ${result.network} address`, secretBox(result.address)),
          result.token ? field(`${result.coin} token on ${result.network}`, secretBox(result.token), result.tokenNote) : callout("amber", result.tokenNote),
          field("Your payment reference", secretBox(result.reference), "Keep it: it identifies this payment if you contact the site owner.")));
        listPayments();
      } catch (error) {
        toast(error.message, true);
      }
      ask.disabled = false;
    }});
    buy.replaceChildren(el("div", {class: "stack"},
      el("p", {class: "help"}, `Pay in ${wallet.coin} on ${wallet.label}, straight to the site owner's wallet. The owner checks the wallet and confirms each payment by hand; your balance then goes up here by itself.`),
      presets,
      field(`Amount in ${COIN}`, amount),
      el("div", {}, ask), details));
  }

  list();
  account();
  listPayments();
  topUp();
}

// ---- Admin -----------------------------------------------------------------------------------
async function drawAdmin(view) {
  if (!me.signedIn) return needSignin("admin");
  if (!me.admin) return go("models", true);
  const check = bubble("Refresh now", {tone: "lime"});
  const setup = el("div");
  const stats = el("div", {class: "stats"}, stat("Accounts", "…"), stat("Credits paid in", "…"), stat("Charged for requests", "…"), stat("Waiting payments", "…"));
  const waiting = el("div");
  const providers = el("div", {}, skeleton(3));
  const wallet = el("div", {}, skeleton(4));
  const prices = el("div", {}, skeleton(6));
  const tools = el("div");
  view.append(pageHead("Admin", "Your site", "Your models, prices, wallet and the payments waiting for you.", check),
    setup, stats, waiting,
    el("div", {class: "section grid2"}, win("Provider connections", providers, {flush: true}), win("Receiving wallet", wallet)),
    el("section", {class: "section"}, sectionHead("Models and prices", `${COIN} per million tokens.`), prices),
    tools);

  check.addEventListener("click", async () => {
    check.disabled = true;
    try {
      const result = await api("/api/admin/refresh", {});
      if (result.refreshing) {
        toast("Discovery is already running. The Models page updates automatically.");
        check.disabled = false;
        return;
      }
      const found = Object.values(result.available || {}).reduce((sum, list) => sum + list.length, 0);
      toast(found ? `Found ${plural(found, "model")}. Every model is on its default price.` : "No models found yet. Provider connections shows why.");
      draw();
    } catch (error) {
      toast(error.message, true);
      check.disabled = false;
    }
  });

  const [overview, walletInfo, catalogue] = await Promise.allSettled([api("/api/admin/overview"), api("/api/wallet"), api("/api/models")]);
  if (overview.status === "fulfilled") {
    const o = overview.value;
    stats.replaceChildren(
      stat("Accounts", count(o.users), "People with an account"),
      stat("Credits paid in", money(o.paid), "Confirmed payments"),
      stat("Charged for requests", cost(o.spent), "At your selling prices"),
      stat("Waiting payments", count(o.waiting.length), o.waiting.length ? "Need your confirmation" : "Nothing to confirm"));
    renderWaiting(waiting, o.waiting);
    renderProviders(providers, o.providers, o.fixes, o.nameTaken);
  } else {
    stats.replaceChildren(callout("red", overview.reason.message));
    providers.replaceChildren(el("div", {class: "loading"}, callout("red", overview.reason.message)));
  }
  if (walletInfo.status === "fulfilled") renderWallet(wallet, walletInfo.value);
  else wallet.replaceChildren(callout("red", walletInfo.reason.message));
  if (catalogue.status === "fulfilled") {
    renderPrices(prices, catalogue.value);
    renderTools(tools, catalogue.value.toolModels);
  }
  else prices.replaceChildren(callout("red", catalogue.reason.message));
  if (catalogue.status === "fulfilled" && walletInfo.status === "fulfilled") {
    const list = catalogue.value.models || [];
    const discovered = list.filter(m => m.discovered);
    const unpriced = discovered.filter(m => !m.available).length;
    const steps = [
      [discovered.length > 0, "Automatic model discovery", "Models appear after setup and stay refreshed automatically."],
      [discovered.length > 0 && unpriced === 0, "Review prices",
        unpriced ? `${plural(unpriced, "model")} without any default ${unpriced === 1 ? "needs" : "need"} your price.` : "Every model starts at the market price. Add your markup."],
      [walletInfo.value.set, "Attach your wallet", "Payments for credits go straight to it."],
    ];
    if (!steps.every(([done]) => done)) {
      setup.replaceChildren(el("section", {class: "setup-card"}, sectionHead("Finish setting up"),
        el("ol", {class: "steps"}, steps.map(([done, title, detail], index) => el("li", {class: done ? "done" : null},
          el("div", {class: "step-head"}, el("span", {class: "label"}, `Step 0${index + 1}`), done ? tag("Done") : tag("To do", "paper")),
          el("div", {class: "step-title"}, title),
          el("div", {class: "help"}, detail))))));
    }
  }
}

function renderWaiting(box, list) {
  if (!list.length) {
    box.replaceChildren();
    return;
  }
  box.replaceChildren(el("section", {class: "section"}, sectionHead("Payments waiting", "Check your wallet before confirming."),
    win(`Waiting · ${list.length}`, el("div", {class: "table-wrap"}, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Reference"), el("th", {}, "Network and address"), el("th", {class: "right"}, "Amount"),
        el("th", {class: "right"}, el("span", {class: "sr-only"}, "Actions")))),
      el("tbody", {}, list.map(p => el("tr", {},
        el("td", {}, el("span", {class: "mono"}, p.reference), el("div", {class: "muted small"}, when(p.created_at))),
        el("td", {}, el("div", {}, p.label || p.network), el("div", {class: "mono muted break"}, p.address)),
        el("td", {class: "right num"}, money(p.dollars)),
        el("td", {class: "right"}, el("div", {class: "row end"},
          flat("Reject", {onclick: async () => {
            const sure = await confirmDialog("Reject this payment request?",
              `Reject it only when no matching ${money(p.dollars)} arrived. No balance is added, and the buyer sees it as rejected.`, "Reject", true);
            if (!sure) return;
            try {
              await api("/api/admin/reject", {reference: p.reference});
              toast("Payment request rejected.");
              refresh();
            } catch (error) {
              toast(error.message, true);
            }
          }}),
          flat("Mark as received", {tone: "blue", onclick: async () => {
            const txId = await inputDialog("Confirm this payment?",
              `Only confirm after checking your wallet: ${money(p.dollars)} on ${p.label || p.network}, with enough confirmations. The balance is added at once and the buyer sees it on their API keys page.`,
              {label: "Transaction id (recommended)", help: "Paste it from your wallet. The site then refuses to count the same transfer for a second request.",
               confirmLabel: "Payment received"});
            if (txId === null) return;
            try {
              await api("/api/admin/confirm", {reference: p.reference, txId});
              toast("Payment confirmed. Balance added.");
              refresh();
            } catch (error) {
              toast(error.message, true);
            }
          }})))))))), {flush: true})));
}

function paymentState(p) {
  if (p.state === "paid") return tag("Received");
  if (p.state === "rejected") return tag("Rejected", "orange", "The site owner found no matching payment.");
  if (p.state === "cancelled") return tag("Cancelled", "paper");
  return tag("Waiting for the owner", "amber", "The site owner checks the wallet and confirms by hand.");
}

// Models the signed-in coding tools offer in their own terminals. They are never sold here.
function renderTools(box, list) {
  const rows = Array.isArray(list) ? list : [];
  if (!rows.length) {
    box.replaceChildren();
    return;
  }
  box.replaceChildren(el("section", {class: "section"},
    sectionHead("Connected coding tools", "Use these in each tool's own terminal. They are not sold on this site and have no website keys."),
    win(`Coding tools · ${rows.length}`, el("div", {class: "table-wrap"}, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Tool"), el("th", {}, "Model"), el("th", {}, "Cost"))),
      el("tbody", {}, rows.map(m => el("tr", {},
        el("td", {}, providerName(m.tool)),
        el("td", {}, el("div", {}, text(m.label)), el("div", {class: "mono muted small"}, text(m.model))),
        el("td", {}, m.free ? tag("Free", "lime round") : el("span", {class: "muted small"}, "Your plan"))))))), {flush: true})));
}

function renderProviders(box, statuses, fixes, taken) {
  // The connections the website sells from, plus any coding tool that needs the admin (a
  // signed-out Codex, say). Healthy tools are listed under Connected coding tools instead.
  const offSite = /coding-tool|terminal|\bclient\b|^not selected/i;
  const rows = Object.entries(statuses || {}).flatMap(([sandbox, list]) =>
    Object.entries(list || {}).map(([provider, status]) => ({sandbox, provider, status: text(status),
      fix: text(fixes && fixes[sandbox] && fixes[sandbox][provider])})))
    .filter(({status}) => !offSite.test(status));
  if (!rows.length) {
    box.replaceChildren(emptyState("Not checked yet", "Discovery runs automatically after setup and retries while providers finish starting or signing in."));
    return;
  }
  // Two sources offering one name: the first keeps it, and the admin sees what was left out.
  const skipped = (Array.isArray(taken) ? taken : []).filter(item => item && item.name);
  const clash = skipped.length ? el("div", {class: "loading"}, callout("amber",
    `Not listed, because another source already sells a model with the same name: ${skipped.map(item => `${text(item.name)} from ${place(item.sandbox)} (kept from ${place(item.owner)})`).join("; ")}.`)) : null;
  box.replaceChildren(clash || "", el("div", {class: "table-wrap"}, el("table", {}, el("tbody", {}, rows.map(row => {
    const {sandbox, provider, status} = row;
    const tone = /^connected$/i.test(status) ? "green" : /not configured|requires|client/i.test(status) ? "amber" : "red";
    const tool = provider.endsWith("-tool");
    const name = provider === sandbox ? (known(BRIDGE, sandbox) ? BRIDGE[sandbox] : sandbox)
      : tool ? `${providerName(provider.slice(0, -5))} (coding tool)` : providerName(provider);
    // A fix names the exact command; it gets its own copy button.
    const command = (/yougori [a-z]+ [^().,]+/.exec(row.fix) || [""])[0].trim();
    return el("tr", {class: "status-row"},
      el("td", {}, el("div", {class: "status-name"}, el("span", {class: `dot ${tone}`}), name)),
      el("td", {class: "muted small"}, place(sandbox)),
      el("td", {class: "small"}, el("div", {}, status),
        row.fix ? el("div", {class: "fix muted"}, el("span", {}, row.fix), command ? copyBracket(command, "copy command") : null) : null));
  })))));
}

function renderWallet(box, info) {
  let network = info.network;
  const address = el("input", {class: "input mono", id: "wallet-address", value: info.address || "", placeholder: info.hint, autocomplete: "off", spellcheck: "false"});
  const help = el("span", {class: "help"}, info.hint);
  const token = el("input", {class: "input mono", id: "wallet-token", value: info.token || "", autocomplete: "off", spellcheck: "false",
    placeholder: "Optional. From Tether's official list for this network"});
  const networks = toggles(info.networks.map(n => [n.value, `${n.label} · ${n.coin}`]), network, value => {
    if (value !== network) token.value = "";
    network = value;
    const chosen = info.networks.find(n => n.value === value);
    help.textContent = chosen ? chosen.hint : "";
    address.placeholder = help.textContent;
  }, "Network");
  const save = bubble("Save wallet", {onclick: async () => {
    if (!network) {
      toast("Choose the payment network first.", true);
      return;
    }
    const value = address.value.trim();
    if (!value) {
      toast("Paste your wallet address first.", true);
      return;
    }
    const contract = token.value.trim();
    if (info.set && (value !== info.address || network !== info.network)) {
      const sure = await confirmDialog("Change the receiving wallet?", "New payment requests will show this address. Requests already made keep the old one.", "Change wallet");
      if (!sure) return;
    }
    save.disabled = true;
    try {
      await api("/api/admin/wallet", {network, address: value, token: contract || null});
      toast("Wallet saved. Customers can buy credits.");
      refresh();
    } catch (error) {
      toast(error.message, true);
      save.disabled = false;
    }
  }});
  box.replaceChildren(el("div", {class: "chooser"},
    info.set
      ? callout("green", "Payments go to ", info.label, ": ", el("span", {class: "mono break"}, info.address),
          info.token ? el("div", {class: "small"}, "USDT token: ", el("span", {class: "mono break"}, info.token)) : null)
      : callout("amber", "Choose which network should receive credit payments, then add your wallet address. Buying credits stays off until you save."),
    el("div", {class: "field"}, el("span", {class: "label"}, "Network"), networks),
    field("Address", address),
    help,
    field("USDT token contract or mint (optional)", token,
      "Copy it from Tether's official list of supported networks. Buyers see it next to your address, so they can check they send Tether USD and not a look-alike token."),
    el("div", {}, save),
    el("p", {class: "help"}, "Only the public address is stored. This site never asks for a private key or recovery phrase.")));
}

function renderPrices(box, data) {
  const markup = Number(data.markup || 0);
  // Models offered now, plus ones that went away but keep a price; never-seen placeholders stay hidden.
  const models = (data.models || []).filter(m => m.discovered || m.priceSource).sort((a, b) => (b.discovered - a.discovered) || rank(a.sandbox) - rank(b.sandbox)
    || makerName(a.maker).localeCompare(makerName(b.maker)) || a.name.localeCompare(b.name));
  const search = el("input", {type: "search", placeholder: "Filter models", "aria-label": "Filter models", autocomplete: "off", spellcheck: "false"});
  const markupInput = el("input", {class: "input compact num", id: "markup", type: "number", min: "0", max: "1000", step: "any", value: String(markup)});
  const body = el("tbody");
  const priceInput = (value, label) => el("input", {class: "input compact num", type: "number", min: "0", max: "10000", step: "any", value: String(value), "aria-label": label});

  const plus = markup ? ` +${markup}%` : "";
  const sourceTag = m => {
    if (m.priceSource === "admin") return tag("Your price", "blue");
    if (m.priceSource === "list") return tag(`List price${plus}`);
    if (m.priceSource === "market") return tag(`Market price${plus}`, "lime round");
    if (m.priceSource === "estimate") return tag(`Estimate${plus}`, "amber");
    if (m.discovered && !m.available) return tag("Needs a price", "orange");
    return tag(m.discovered ? "Priced" : "Not discovered", "paper");
  };
  const details = m => [
    m.costIn != null ? el("div", {class: "muted small"}, `Cost ${perMillion(m.costIn)} / ${perMillion(m.costOut)}`) : null,
    m.marketIn != null ? el("div", {class: "muted small"}, `Market ${perMillion(m.marketIn)} / ${perMillion(m.marketOut)}`) : null,
    m.promoEnds ? el("div", {class: "muted small"}, `Introductory price until ${new Date(m.promoEnds + "T00:00:00").toLocaleDateString(undefined, {dateStyle: "medium"})}`) : null,
  ];
  const save = async (m, inInput, outInput) => {
    const priceIn = Number(inInput.value);
    const priceOut = Number(outInput.value);
    if (inInput.value === "" || outInput.value === "" || !(priceIn >= 0 && priceIn <= 10000 && priceOut >= 0 && priceOut <= 10000)) {
      toast(`Enter both prices in ${COIN} per million tokens, from 0 to 10,000.`, true);
      return;
    }
    if (m.costIn != null && (priceIn < m.costIn || priceOut < m.costOut)) {
      const sure = await confirmDialog("Sell below your cost?",
        `This model costs you ${perMillion(m.costIn)} input and ${perMillion(m.costOut)} output per million tokens. At this price every request loses money.`,
        "Save anyway", true);
      if (!sure) return;
    } else if (priceIn === 0 && priceOut === 0) {
      const sure = await confirmDialog("Make this model free?",
        Number(m.costIn) > 0 || Number(m.costOut) > 0 ? "Customers will pay nothing for it, and you pay for every request." : "Customers will pay nothing for it.",
        "Make it free", true);
      if (!sure) return;
    }
    try {
      await api("/api/admin/price", {name: m.name, priceIn, priceOut});
      Object.assign(m, {priceIn, priceOut, priceSource: "admin", available: m.discovered});
      renderRows();
      toast("Price saved.");
    } catch (error) {
      toast(error.message, true);
    }
  };
  const reset = async m => {
    try {
      const result = await api("/api/admin/price/reset", {name: m.name});
      Object.assign(m, {priceIn: result.priceIn, priceOut: result.priceOut, priceSource: m.defaultSource || "list", available: m.discovered});
      renderRows();
      toast("Back on the default price.");
    } catch (error) {
      toast(error.message, true);
    }
  };
  function renderRows() {
    const query = search.value.trim().toLowerCase();
    const rows = models.filter(m => !query || `${m.name} ${makerName(m.maker)}`.toLowerCase().includes(query));
    if (!rows.length) {
      body.replaceChildren(el("tr", {}, el("td", {colspan: "5"}, emptyState("No models match", "Try another word."))));
      return;
    }
    let grouped = false;
    body.replaceChildren(...rows.flatMap(m => {
      const inInput = priceInput(m.priceIn, `Input price for ${m.name}`);
      const outInput = priceInput(m.priceOut, `Output price for ${m.name}`);
      const head = [];
      if (!m.discovered && !grouped) {
        grouped = true;
        head.push(el("tr", {class: "group-row"}, el("td", {colspan: "5"}, "Not offered right now")));
      }
      return [...head, el("tr", {},
        el("td", {}, el("div", {class: "mono"}, m.name), el("div", {class: "muted small"}, makerName(m.maker))),
        el("td", {}, el("div", {class: "stack-tight"}, sourceTag(m), details(m))),
        el("td", {}, inInput),
        el("td", {}, outInput),
        el("td", {class: "right"}, el("div", {class: "row end"},
          m.defaultIn != null && m.priceSource === "admin" ? bracket("default", () => reset(m), {title: "Use the default price", aria: `Use the default price for ${m.name}`}) : null,
          flat("Save", {onclick: () => save(m, inInput, outInput)}))))];
    }));
  }
  search.addEventListener("input", renderRows);
  renderRows();

  const apply = flat("Apply", {tone: "blue", onclick: async () => {
    const percent = Number(markupInput.value);
    if (markupInput.value === "" || !(percent >= 0 && percent <= 1000)) {
      toast("Use a markup from 0 to 1000 percent.", true);
      return;
    }
    apply.disabled = true;
    try {
      const result = await api("/api/admin/markup", {percent});
      toast(result.changed ? `Markup saved. ${plural(result.changed, "price")} updated.` : "Markup saved.");
      renderPrices(box, await api("/api/models"));
    } catch (error) {
      toast(error.message, true);
      apply.disabled = false;
    }
  }});
  const sources = Object.entries(data.priceSources || {});
  const checked = data.pricesAsOf ? new Date(data.pricesAsOf + "T00:00:00").toLocaleDateString(undefined, {dateStyle: "long"}) : "";
  box.replaceChildren(win("Prices", [
    el("div", {class: "price-tools"},
      el("label", {class: "address"}, pixelIcon("search"), search),
      el("span", {class: "spacer"}),
      el("div", {class: "markup"}, el("label", {for: "markup", class: "label"}, "Markup on default prices"), markupInput, el("span", {class: "label"}, "%"), apply)),
    !markup && models.some(m => ["list", "market", "estimate"].includes(m.priceSource)) ? el("div", {class: "price-hint"},
      callout("blue", "At 0% markup you sell at the market price, and at cost where the market charges what the provider does. Add a markup to earn more on each request.")) : null,
    el("div", {class: "table-wrap"}, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Model"), el("th", {}, "Price"), el("th", {}, "Input /1M"), el("th", {}, "Output /1M"),
        el("th", {class: "right"}, el("span", {class: "sr-only"}, "Actions")))),
      body))], {flush: true, foot: [pixelIcon("star"), el("span", {},
      "Prices checked",
      checked ? ` (checked ${checked}` : "",
      sources.length ? [": ", sources.map(([provider, url], index) => [index ? ", " : "",
        el("a", {href: url, target: "_blank", rel: "noopener noreferrer"}, provider === "market" ? "OpenRouter market" : providerName(provider))])] : "",
      checked ? ")" : "",
      ". Every model starts at the market price, never below what it costs you; introductory prices switch to the regular price on their end date by themselves. "
        + "Models on your GPU start at the market rate for their size. Models nobody prices publicly get a cautious estimate. "
        + "Your markup goes on top. Prices you save yourself are never changed; [default] puts a model back on its default price.")]}));
}

addEventListener("popstate", () => {
  current = routeFromLocation();
  draw();
});
current = routeFromLocation();
const lift = veil();
refresh().finally(lift);
"""


def shell(site_name):
    safe = (site_name or "My API").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#ebedf5">
<title>{safe}</title>
<script src="/theme.js"></script>
<link rel="stylesheet" href="/app.css">
</head><body>
<div class="crt" aria-hidden="true"><div class="crt-grain"></div><div class="crt-vignette"></div><div class="crt-glare"></div><div class="crt-scan"></div><div class="crt-bezel"></div></div>
<div id="top"></div>
<main id="view"><noscript>This site needs JavaScript to show your models, keys and credits.</noscript></main>
<footer class="foot" id="foot"></footer>
<script src="/app.js"></script>
</body></html>"""

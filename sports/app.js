const MSG = { wrong: "Wrong password", load: "Could not load. Try again.", empty: "No match days yet", nohl: "No highlights yet" };
const NF = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const round1 = (x) => Math.sign(x) * Math.round(Math.abs(x) * 10) / 10;
const r6 = (x) => Math.round(x * 1e6) / 1e6;
const same = (a, b) => Number(a) === Number(b);
const byName = (a, b) => String(a).localeCompare(String(b), "en");
const nameOf = (d, p) => d?.people?.[String(p)]?.name ?? String(p);
const isDay = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
const addDays = (iso, n) => {
  const t = new Date(iso + "T00:00:00Z");
  t.setUTCDate(t.getUTCDate() + n);
  return t.toISOString().slice(0, 10);
};

export function message(kind) {
  return MSG[kind] ?? "";
}

export async function decrypt(bytes, password) {
  const pw = typeof password === "string" ? password.trim() : "";
  if (!pw) throw new Error(MSG.wrong);
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes ?? []);
  if (b.length < 44) throw new Error(MSG.wrong);
  try {
    const s = globalThis.crypto.subtle;
    const base = await s.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    const key = await s.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b.slice(0, 16), iterations: 600000 },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = await s.decrypt({ name: "AES-GCM", iv: b.slice(16, 28) }, key, b.slice(28));
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new Error(MSG.wrong);
  }
}

export function fmt(x) {
  const r = round1(Number(x));
  if (!r) return "0";
  return (r > 0 ? "+" : "−") + NF.format(Math.abs(r));
}

const num = (x) => NF.format(round1(Number(x) || 0) || 0);

export function inPeriod(d, period = "all") {
  const all = d?.matchdays ?? [];
  if (period !== "month" && period !== "week") return all.slice();
  const u = d.updated;
  if (!isDay(u)) return [];
  if (period === "month") return all.filter((m) => m.date.slice(0, 7) === u.slice(0, 7));
  const mon = addDays(u, -((new Date(u + "T00:00:00Z").getUTCDay() + 6) % 7));
  const sun = addDays(mon, 6);
  return all.filter((m) => m.date >= mon && m.date <= sun);
}

const order = (d, totals) => Object.keys(totals).map(Number)
  .sort((a, b) => totals[b] - totals[a] || byName(nameOf(d, a), nameOf(d, b)));

export function ladder(d, period = "all") {
  const tot = {}, cnt = {}, won = {};
  for (const m of inPeriod(d, period)) {
    for (const p of m.players) {
      tot[p.person] = (tot[p.person] || 0) + p.net;
      cnt[p.person] = (cnt[p.person] || 0) + 1;
      won[p.person] = (won[p.person] || 0) + (p.net > 0 ? 1 : 0);
    }
  }
  for (const k in tot) tot[k] = r6(tot[k]);
  return order(d, tot).map((person, i) => ({
    rank: i + 1, person, name: nameOf(d, person), total: tot[person], matches: cnt[person], wins: won[person],
  }));
}

const topOf = (d, md) => md.players.reduce((best, p) => (!best || p.net > best.net
  || (p.net === best.net && byName(nameOf(d, p.person), nameOf(d, best.person)) < 0) ? p : best), null);

export function matchdayRows(d, period = "all") {
  return inPeriod(d, period).map((md) => {
    const t = topOf(d, md);
    return {
      n: md.n, date: md.date, tag: md.tag, top: t ? t.person : null,
      topName: t ? nameOf(d, t.person) : "", topNet: t ? t.net : 0, players: md.players.length,
    };
  }).reverse();
}

export function detail(md, d) {
  return md.players.map((p) => {
    const r = { person: p.person, name: nameOf(d, p.person), in: p.in, out: p.out, net: p.net };
    if (p.handle != null) r.handle = p.handle;
    if (p.device != null) r.device = p.device;
    return r;
  }).sort((a, b) => b.net - a.net || byName(a.name, b.name));
}

const markOf = (n) => (n > 0 ? "W" : n < 0 ? "L" : "D");

export function form(d, person, count = 5, period = "all") {
  const nets = [];
  for (const m of inPeriod(d, period)) for (const p of m.players) if (same(p.person, person)) nets.push(p.net);
  return count > 0 ? nets.slice(-count).map(markOf) : [];
}

function running(d, period) {
  const days = inPeriod(d, period), tot = {}, vals = {}, played = {};
  days.forEach((m, i) => {
    for (const p of m.players) {
      tot[p.person] = (tot[p.person] || 0) + p.net;
      (played[p.person] ||= new Set()).add(i);
    }
    for (const k in tot) (vals[k] ||= Array(days.length).fill(null))[i] = r6(tot[k]);
  });
  return { days, vals, played };
}

export function race(d, period = "all") {
  const { vals, played } = running(d, period), out = {};
  for (const k in vals) out[k] = vals[k].filter((_, i) => played[k].has(i));
  return out;
}

export function stats(d, person) {
  let best = null, worst = null, played = 0, won = 0;
  for (const m of d?.matchdays ?? []) {
    for (const p of m.players) {
      if (!same(p.person, person)) continue;
      played++;
      if (p.net > 0) won++;
      if (!best || p.net > best.net) best = { net: p.net, date: m.date };
      if (!worst || p.net < worst.net) worst = { net: p.net, date: m.date };
    }
  }
  return { best, worst, played, winRate: played ? Math.round(100 * won / played) : 0 };
}

function pick(d, cands, score) {
  let best = null;
  for (const c of cands) {
    if (!best) { best = c; continue; }
    const diff = r6(score(c) - score(best));
    if (diff > 0 || (diff === 0 && (c.date < best.date
      || (c.date === best.date && byName(nameOf(d, c.person), nameOf(d, best.person)) < 0)))) best = c;
  }
  return best;
}

export function records(d, period = "all") {
  const { days, vals, played } = running(d, period);
  const dayC = [], winC = [], loseC = [], topC = [], matchC = [], backC = [], busyC = [], downC = [], peakC = [];
  const runs = {}, tops = {}, cnt = {};
  days.forEach((m, i) => {
    let inSum = 0;
    for (const p of m.players) {
      const k = p.person;
      inSum += Number(p.in) || 0;
      dayC.push({ person: k, value: p.net, date: m.date });
      const r = runs[k] ||= { w: 0, l: 0, wFrom: null, lFrom: null };
      if (p.net > 0) { r.w = r.w ? r.w + 1 : 1; if (r.w === 1) r.wFrom = m.date; } else r.w = 0;
      if (p.net < 0) { r.l = r.l ? r.l + 1 : 1; if (r.l === 1) r.lFrom = m.date; } else r.l = 0;
      if (r.w) winC.push({ person: k, value: r.w, date: m.date, from: r.wFrom });
      if (r.l) loseC.push({ person: k, value: r.l, date: m.date, from: r.lFrom });
      cnt[k] = (cnt[k] || 0) + 1;
      matchC.push({ person: k, value: cnt[k], date: m.date });
      const bk = p.back;
      if (bk && Number.isFinite(bk.low) && Number.isFinite(bk.end) && r6(bk.end - bk.low) > 0) {
        backC.push({ person: k, value: r6(bk.end - bk.low), date: m.date, low: bk.low, end: bk.end });
      }
    }
    busyC.push({ value: m.players.length, date: m.date, total: r6(inSum), n: m.n });
    const t = topOf(d, m);
    if (t) { tops[t.person] = (tops[t.person] || 0) + 1; topC.push({ person: t.person, value: tops[t.person], date: m.date }); }
  });
  for (const k in vals) {
    const person = Number(k);
    let peak = null;
    vals[k].forEach((v, i) => {
      if (!played[k].has(i)) return;
      const date = days[i].date;
      if (!peak || v > peak.v) peak = { v, date };
      else if (v < peak.v) downC.push({ person, value: r6(v - peak.v), date, from: peak.date, peak: peak.v, low: v });
      peakC.push({ person, value: v, date });
    });
  }
  const up = (c) => c.value, dn = (c) => -c.value;
  return {
    bestDay: pick(d, dayC, up), worstDay: pick(d, dayC, dn), winRun: pick(d, winC, up), loseRun: pick(d, loseC, up),
    mostTops: pick(d, topC, up), mostMatches: pick(d, matchC, up), comeback: pick(d, backC, up),
    busiest: pick(d, busyC, up), downswing: pick(d, downC, dn), peak: pick(d, peakC, up),
  };
}

const advKeys = (d) => (d?.labels?.adv ?? []).map((a) => a[0]);

export function advanced(d, period = "all") {
  const keys = advKeys(d);
  if (keys.length < 6) return [];
  const [kh, kv, kp, ks, kw, ka] = keys, sum = {};
  for (const m of inPeriod(d, period)) {
    for (const p of m.players) {
      if (!p.adv) continue;
      const s = sum[p.person] ||= Object.fromEntries(keys.map((k) => [k, 0]));
      for (const k of keys) s[k] += Number(p.adv[k]) || 0;
    }
  }
  const pct = (a, b) => (b ? Math.round(100 * a / b) : 0);
  return Object.keys(sum).map(Number).filter((p) => sum[p][kh] > 0).map((p) => {
    const s = sum[p];
    return { person: p, name: nameOf(d, p), [kh]: s[kh], [ka]: s[ka], [kv]: pct(s[kv], s[kh]),
      [kp]: pct(s[kp], s[kh]), [ks]: pct(s[ks], s[kh]), [kw]: pct(s[kw], s[ks]) };
  }).sort((a, b) => b[kh] - a[kh] || byName(a.name, b.name));
}

export function stylePoints(d, period = "all") {
  const [kh, kv, kp] = advKeys(d);
  return advanced(d, period).filter((r) => r[kh] >= 50).map((r) => ({ person: r.person, name: r.name, x: r[kv], y: r[kp], w: r[kh] }));
}

export function rankOverTime(d, period = "all") {
  const { days, vals } = running(d, period), out = {};
  for (const k in vals) out[k] = Array(days.length).fill(null);
  days.forEach((_, i) => {
    const tot = {};
    for (const k in vals) if (vals[k][i] != null) tot[k] = vals[k][i];
    order(d, tot).forEach((p, r) => { out[p][i] = r + 1; });
  });
  return out;
}

export function headToHead(d, period = "all") {
  const days = inPeriod(d, period), cnt = {};
  for (const m of days) for (const p of m.players) cnt[p.person] = (cnt[p.person] || 0) + 1;
  const people = Object.keys(cnt).map(Number)
    .sort((a, b) => cnt[b] - cnt[a] || byName(nameOf(d, a), nameOf(d, b))).slice(0, 8);
  const wins = {};
  for (const a of people) for (const b of people) if (a !== b) wins[`${a}-${b}`] = 0;
  for (const m of days) {
    const net = {};
    for (const p of m.players) net[p.person] = p.net;
    for (const a of people) {
      for (const b of people) if (a !== b && a in net && b in net && net[a] > net[b]) wins[`${a}-${b}`]++;
    }
  }
  return { people, wins };
}

export function activity(d, period = "all") {
  return inPeriod(d, period).map((m) => ({
    date: m.date, tag: m.tag, total: r6(m.players.reduce((s, p) => s + (Number(p.in) || 0), 0)),
  }));
}

export function candles(d, person) {
  let run = 0;
  const out = [];
  for (const m of d?.matchdays ?? []) {
    for (const p of m.players) {
      if (!same(p.person, person)) continue;
      const open = r6(run);
      run += p.net;
      const close = r6(run);
      const hi = Number.isFinite(p.adv?.hi) ? open + p.adv.hi : -Infinity;
      const lo = Number.isFinite(p.adv?.lo) ? open + p.adv.lo : Infinity;
      out.push({ date: m.date, tag: m.tag, open, close, high: r6(Math.max(open, close, hi)), low: r6(Math.min(open, close, lo)) });
    }
  }
  return out;
}

const BOARD_AT = [0, 3, 4, 5];

export function frames(h) {
  const acts = h?.actions ?? [], shown = h?.shown ?? {}, board = h?.board ?? [];
  const out = new Set();
  let total = 0, street = 0, put = {};
  return acts.map((a, i) => {
    const st = Number.isInteger(a.street) ? Math.min(3, Math.max(0, a.street)) : street;
    if (st !== street) { street = st; put = {}; }
    const add = Number(a.add) || 0;
    total += add;
    if (a.w === "lets it go") out.add(a.seat);
    if (add > 0) put[a.seat] = Number.isFinite(a.to) ? a.to : (put[a.seat] || 0) + add;
    const end = a.w === "wins" || i === acts.length - 1;
    return {
      seat: a.seat, w: a.w, add, to: a.to, street, total: end ? h.collected : r6(total),
      board: board.slice(0, BOARD_AT[street]).map((c) => c.slice()),
      shown: Object.fromEntries(Object.entries(shown).map(([k, v]) => [k, v.map((c) => c.slice())])),
      out: [...out], put: { ...put },
    };
  });
}

export function choose(pool, rnd, last) {
  if (!pool || !pool.length) return null;
  if (pool.length === 1) return pool[0];
  const lk = last == null ? null : JSON.stringify(last);
  const rest = pool.filter((h) => h !== last && JSON.stringify(h) !== lk);
  const from = rest.length ? rest : pool;
  const r = Number.isFinite(rnd) ? Math.min(Math.max(rnd, 0), 1 - 1e-9) : Math.random();
  return from[Math.floor(r * from.length)];
}

export function route(hash) {
  const s = String(hash ?? "").replace(/^#/, "");
  if (s === "ladder" || s === "history" || s === "highlights" || /^(player|history)-\d+$/.test(s)) return s;
  return "ladder";
}

const NS = "http://www.w3.org/2000/svg";
const WD = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MO = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const KINDS = [["return", "Best return"], ["big", "Biggest rally"], ["smash", "Most smashes"], ["fake", "Best fake"]];
const S = { d: null, view: "", period: "all", showAll: false, open: new Set(), mode: "candle", hl: null, stop: () => {} };

const css = (name) => `var(${name})`;
const dayLabel = (iso) => {
  if (!isDay(iso)) return "";
  const t = new Date(iso + "T00:00:00Z");
  return `${WD[t.getUTCDay()]} ${String(t.getUTCDate()).padStart(2, "0")} ${MO[t.getUTCMonth()]}`;
};
const shortLabel = (iso) => dayLabel(iso).slice(4);
const tone = (x) => { const s = fmt(x); return s[0] === "+" ? "up" : s[0] === "−" ? "down" : ""; };

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k instanceof Node ? k : String(k));
  return n;
}

function sv(tag, attrs, text) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if ((k === "fill" || k === "stroke") && String(v).startsWith("var(")) n.style.setProperty(k, v);
    else n.setAttribute(k, v);
  }
  if (text != null) n.textContent = text;
  return n;
}

const ballmark = () => el("span", { class: "ballmark" });
const tagChip = (tag) => el("span", { class: "tagc " + (tag === "home" ? "home" : "onli") }, tag === "home" ? "Home" : "Onli");
const formNode = (marks, slots = marks.length) => el("div", { class: "form" }, [
  ...Array.from({ length: Math.max(0, slots - marks.length) }, () => el("b", { class: "E" }, "")),
  ...marks.map((m) => el("b", { class: m }, m)),
]);
const pnlParts = (x) => {
  const [whole, part] = fmt(x).split(".");
  return [whole, el("small", { class: "dp" }, part ? "." + part : "")];
};
const press = (e) => {
  const a = e.target.closest?.("a.link");
  if (!a || e.pointerType === "mouse") return;
  a.classList.add("press");
  setTimeout(() => a.classList.remove("press"), 220);
};
const chev = () => el("span", { class: "chev", "aria-hidden": "true" }, "›");
const who = (d, p) => el("a", { class: "who", href: "#player-" + p }, nameOf(d, p));

function scale(min, max, ticks = 5) {
  const raw = Math.max(max - min, 1) / ticks, p = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * p).find((s) => s >= raw - 1e-9);
  const lo = Math.floor(min / step) * step;
  return { lo, hi: Math.max(Math.ceil(max / step) * step, lo + step), step };
}

const narrow = () => typeof matchMedia === "function" && matchMedia("(max-width: 600px)").matches;
const chartW = (w) => (narrow() ? 400 : w);

const labelAt = (n, max = narrow() ? 4 : 8) => {
  const every = Math.max(1, Math.ceil(n / max));
  return (i) => (n - 1 - i) % every === 0;
};

function svgBox(W, H) {
  return sv("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
}

function txt(svg, x, y, str, a = {}) {
  svg.append(sv("text", Object.assign({ x, y, fill: css("--chalk"), "font-size": 12, "font-family": "Barlow, sans-serif" }, a), str));
}

function gridLine(svg, x1, x2, y, strong) {
  svg.append(sv("line", { x1, x2, y1: y, y2: y, stroke: strong ? css("--chalk") : css("--board-line"),
    "stroke-width": strong ? 1.5 : 1, "stroke-opacity": strong ? 0.6 : 1 }));
}

function spread(ends, top, bottom, gap) {
  const idx = ends.map((_, i) => i).sort((a, b) => ends[a] - ends[b]);
  for (let k = 1; k < idx.length; k++) if (ends[idx[k]] - ends[idx[k - 1]] < gap) ends[idx[k]] = ends[idx[k - 1]] + gap;
  for (let k = idx.length - 1; k >= 0; k--) {
    const limit = k === idx.length - 1 ? bottom : ends[idx[k + 1]] - gap;
    if (ends[idx[k]] > limit) ends[idx[k]] = limit;
  }
  for (const i of idx) ends[i] = Math.max(ends[i], top);
}

function lineStyle(rank, count) {
  if (rank === 1) return [css("--ball"), 1];
  if (rank === 2) return [css("--up"), 1];
  if (rank === 3) return ["#6fa8ee", 1];
  if (rank === count && count > 3) return [css("--down"), 1];
  if (rank === count - 1 && count > 4) return [css("--onli"), 1];
  return [css("--chalk"), 0.5];
}

function segGap(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax, dy = by - ay, len = dx * dx + dy * dy;
  const t = len ? Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / len)) : 0;
  return Math.hypot(px - ax - t * dx, py - ay - t * dy);
}

function gapTo(pts, px, py) {
  const p = pts.filter(Boolean);
  let g = p.length ? Math.hypot(px - p[0][0], py - p[0][1]) : Infinity;
  for (let j = 1; j < p.length; j++) g = Math.min(g, segGap(px, py, p[j - 1], p[j]));
  return g;
}

function hoverLayer(svg, dates, x, left, top, paint) {
  const n = dates.length, layer = sv("g", { class: "hov" }), peek = el("div", { class: "peek", hidden: true });
  let hot = null, touch = false;
  const focus = (node) => {
    hot?.classList.remove("hot");
    hot = node;
    node?.classList.add("hot");
    svg.classList.toggle("focus", !!node);
  };
  const hide = (e) => {
    if (e && svg.parentNode?.contains(e.target)) return;
    focus(null);
    layer.remove();
    peek.hidden = true;
    touch = false;
    document.removeEventListener("pointerdown", hide);
  };
  const show = (e) => {
    const r = svg.getBoundingClientRect(), box = svg.parentNode;
    if (!r.width || !box || !n) return;
    const k = svg.viewBox.baseVal.width / r.width, sx = (e.clientX - r.left) * k, sy = (e.clientY - r.top) * k;
    let i = 0;
    for (let j = 1; j < n; j++) if (Math.abs(x(j) - sx) < Math.abs(x(i) - sx)) i = j;
    layer.replaceChildren();
    const out = paint(i, { sx, sy, k, gx: x(i), layer });
    focus(out.node ?? null);
    svg.append(layer);
    peek.replaceChildren(el("b", {}, shortLabel(dates[i])), ...out.nodes);
    if (!peek.isConnected) box.append(peek);
    peek.hidden = false;
    const br = box.getBoundingClientRect(), ox = r.left - br.left - box.clientLeft, oy = r.top - br.top - box.clientTop;
    const cw = box.clientWidth, ch = box.clientHeight, lx = ox + x(i) / k;
    peek.classList.remove("two");
    if (peek.offsetHeight > ch - 8) peek.classList.add("two");
    const w = peek.offsetWidth, h = peek.offsetHeight;
    let px = lx + 12;
    if (px + w > cw - 4) px = lx - 12 - w;
    peek.style.left = Math.max(ox + left / k, Math.min(px, cw - 4 - w)) + "px";
    peek.style.top = Math.max(4, Math.min(oy + top / k, ch - 4 - h)) + "px";
  };
  svg.classList.add("live");
  svg.addEventListener("pointermove", (e) => { if (e.pointerType === "mouse" || touch) show(e); });
  svg.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse") return;
    show(e);
    if (!touch) document.addEventListener("pointerdown", hide);
    touch = true;
  });
  svg.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") hide(); });
}

const linePaint = (lines, top, bottom, row) => (i, { sx, sy, k, gx, layer }) => {
  let best = null, gap = 8 * k;
  for (const ln of lines) {
    const g = gapTo(ln.pts, sx, sy);
    if (g <= gap) { best = ln; gap = g; }
  }
  layer.append(sv("line", { x1: gx, x2: gx, y1: top, y2: bottom, stroke: css("--chalk"), "stroke-opacity": 0.55, "stroke-dasharray": "3 3" }));
  const list = [];
  for (const ln of lines) {
    const p = ln.pts[i];
    if (!p) continue;
    layer.append(sv("circle", { cx: p[0], cy: p[1], r: ln === best ? 5.5 : 3.5, fill: ln.col, "fill-opacity": ln === best ? 1 : Math.max(ln.op, 0.6), stroke: css("--board"), "stroke-width": 1.5 }));
    list.push({ ln, ...row(ln.person, i) });
  }
  list.sort((a, b) => a.key - b.key || byName(a.ln.name, b.ln.name));
  return { node: best?.g, nodes: [el("div", { class: "rows" }, list.map((o) => el("div", { class: "pr" + (o.ln === best ? " hot" : "") },
    el("i", { style: `background:${o.ln.col};opacity:${o.ln.op}` }), el("span", {}, o.ln.name),
    el("em", { class: o.cls || null }, o.value), el("small", { class: o.dcls || null }, o.change ?? ""))))] };
};

function raceChart(d, period, rows) {
  const { days, vals, played } = running(d, period), n = days.length;
  const W = chartW(700), L = 56, R = 130, T = 14, B = 30, H = Math.max(320, rows.length * 17 + T + B + 10);
  const all = [0, ...Object.values(vals).flat().filter((v) => v != null)];
  const { lo, hi, step } = scale(Math.min(...all), Math.max(...all));
  const x = (i) => L + (W - L - R) * (n === 1 ? 0.5 : i / (n - 1));
  const y = (v) => T + (H - T - B) * (1 - (v - lo) / (hi - lo));
  const svg = svgBox(W, H);
  for (let v = lo; v <= hi + 1e-9; v += step) {
    gridLine(svg, L, W - R, y(v), Math.abs(v) < 1e-9);
    txt(svg, L - 8, y(v) + 4, fmt(v), { "text-anchor": "end", "fill-opacity": 0.7 });
  }
  const show = labelAt(n);
  days.forEach((m, i) => { if (show(i)) txt(svg, x(i), H - 9, shortLabel(m.date), { "text-anchor": "middle", "fill-opacity": 0.7 }); });
  const drawn = rows.slice().reverse();
  const ends = drawn.map((r) => y(vals[r.person][n - 1]) + 5);
  spread(ends, T + 5, H - B, 17);
  const lines = drawn.map((r, k) => {
    const [col, op] = lineStyle(r.rank, rows.length), pts = vals[r.person], g = sv("g", { class: "ln" });
    const at = pts.map((v, i) => (v == null ? null : [x(i), y(v)]));
    const dPath = at.filter(Boolean).map(([px, py], i) => (i ? "L" : "M") + px.toFixed(1) + " " + py.toFixed(1)).join(" ");
    g.append(sv("path", { d: dPath, fill: "none", stroke: col, "stroke-opacity": op, "stroke-width": op < 1 ? 1.5 : 2.5,
      "stroke-linejoin": "round", "stroke-linecap": "round" }));
    g.append(sv("circle", { cx: x(n - 1), cy: y(pts[n - 1]), r: op < 1 ? 3 : 4.5, fill: col, "fill-opacity": op }));
    txt(g, x(n - 1) + 10, ends[k], `${r.name} ${fmt(r.total)}`, { fill: col, "fill-opacity": op < 1 ? 0.75 : 1,
      "font-size": 15, "font-weight": 600, "font-family": "'Barlow Condensed', sans-serif" });
    svg.append(g);
    return { person: r.person, name: r.name, col, op, g, pts: at };
  });
  hoverLayer(svg, days.map((m) => m.date), x, L, T, linePaint(lines, T, H - B, (p, i) => {
    const v = vals[p][i], dv = v - (i ? vals[p][i - 1] ?? 0 : 0), on = played[p].has(i);
    return { key: -v, value: fmt(v), cls: tone(v), change: on ? fmt(dv) : null, dcls: on ? tone(dv) : null };
  }));
  return svg;
}

function rankChart(d, period, rows) {
  const ranks = rankOverTime(d, period), days = inPeriod(d, period), n = days.length, N = rows.length;
  const W = chartW(716), L = 40, R = 96, T = 16, B = 30, H = Math.max(250, N * 16 + T + B);
  const x = (i) => L + (W - L - R) * (n === 1 ? 0.5 : i / (n - 1));
  const y = (r) => T + (H - T - B) * (N === 1 ? 0 : (r - 1) / (N - 1));
  const svg = svgBox(W, H), tickStep = Math.max(1, Math.ceil((N - 1) / 3));
  const ticks = [];
  for (let r = 1; r <= N; r += tickStep) ticks.push(r);
  if (ticks[ticks.length - 1] !== N) ticks.push(N);
  for (const r of ticks) { gridLine(svg, L, W - R, y(r)); txt(svg, L - 8, y(r) + 4, String(r), { "text-anchor": "end", "fill-opacity": 0.7 }); }
  const show = labelAt(n);
  days.forEach((m, i) => { if (show(i)) txt(svg, x(i), H - 9, shortLabel(m.date), { "text-anchor": "middle", "fill-opacity": 0.7 }); });
  const lines = rows.slice().reverse().map((r) => {
    const [col, op] = lineStyle(r.rank, N), g = sv("g", { class: "ln" });
    const at = ranks[r.person].map((v, i) => (v == null ? null : [x(i), y(v)])), pts = at.filter(Boolean);
    g.append(sv("polyline", { points: pts.map((p) => p.join(",")).join(" "), fill: "none", stroke: col, "stroke-opacity": op,
      "stroke-width": op < 1 ? 1.5 : 2.5, "stroke-linejoin": "round" }));
    const [ex, ey] = pts[pts.length - 1];
    g.append(sv("circle", { cx: ex, cy: ey, r: 4, fill: col, "fill-opacity": op }));
    txt(g, ex + 10, ey + 4, r.name, { fill: col, "fill-opacity": op < 1 ? 0.75 : 1, "font-weight": 600, "font-size": 13 });
    svg.append(g);
    return { person: r.person, name: r.name, col, op, g, pts: at };
  });
  hoverLayer(svg, days.map((m) => m.date), x, L, T, linePaint(lines, T, H - B, (p, i) => {
    const v = ranks[p][i], was = i ? ranks[p][i - 1] : null, dv = was == null ? 0 : was - v;
    const on = !!dv && days[i].players.some((q) => same(q.person, p));
    return { key: v, value: "#" + v, change: on ? (dv > 0 ? "▲" : "▼") + Math.abs(dv) : null, dcls: on ? (dv > 0 ? "up" : "down") : null };
  }));
  return svg;
}

function activityChart(rows, days) {
  const W = chartW(716), H = 190, L = 52, R = 16, T = 22, B = 30, n = rows.length;
  const { hi, step } = scale(0, Math.max(1, ...rows.map((r) => r.total)), 3);
  const y = (v) => T + (H - T - B) * (hi - v) / hi, slot = (W - L - R) / n, bw = Math.max(2, Math.min(48, slot - 6));
  const svg = svgBox(W, H), show = labelAt(n);
  for (let v = 0; v <= hi + 1e-9; v += step) {
    gridLine(svg, L, W - R, y(v), v === 0);
    txt(svg, L - 8, y(v) + 4, num(v), { "text-anchor": "end", "fill-opacity": 0.7 });
  }
  const X = (i) => L + slot * i + slot / 2;
  const bars = rows.map((r, i) => {
    const cx = X(i), bar = sv("rect", { class: "mark", x: cx - bw / 2, y: y(r.total), width: bw, height: y(0) - y(r.total),
      fill: css(r.tag === "home" ? "--ball" : "--onli") });
    svg.append(bar);
    if (n <= (narrow() ? 6 : 12)) txt(svg, cx, y(r.total) - 6, num(r.total), { "text-anchor": "middle", "font-weight": 600 });
    if (show(i)) txt(svg, cx, H - 9, shortLabel(r.date), { "text-anchor": "middle", "fill-opacity": 0.7 });
    return bar;
  });
  hoverLayer(svg, rows.map((r) => r.date), X, L, T, (i) => {
    const r = rows[i], home = r.tag === "home", cnt = days[i]?.players.length ?? 0;
    return { node: bars[i], nodes: [el("div", { class: "facts" }, el("span", { class: home ? "home" : "onli" }, home ? "Home" : "Online"),
      el("span", {}, `${num(r.total)} balls in play`), el("span", {}, `${cnt} ${cnt === 1 ? "player" : "players"}`))] };
  });
  return svg;
}

function styleChart(d, pts) {
  const W = chartW(716), H = 300, L = 52, R = 20, T = 18, B = 42;
  const XM = Math.max(70, Math.ceil(Math.max(0, ...pts.map((p) => p.x)) / 10) * 10);
  const YM = Math.max(40, Math.ceil(Math.max(0, ...pts.map((p) => p.y)) / 10) * 10);
  const x = (v) => L + (W - L - R) * v / XM, y = (v) => T + (H - T - B) * (YM - v) / YM, svg = svgBox(W, H);
  const names = d.labels?.adv ?? [];
  for (let v = 0; v <= YM; v += 10) { gridLine(svg, L, W - R, y(v), v === 0); txt(svg, L - 8, y(v) + 4, v + "%", { "text-anchor": "end", "fill-opacity": 0.7 }); }
  for (let v = 10; v <= XM; v += 10) {
    svg.append(sv("line", { x1: x(v), x2: x(v), y1: T, y2: y(0), stroke: css("--board-line") }));
    txt(svg, x(v), y(0) + 16, v + "%", { "text-anchor": "middle", "fill-opacity": 0.7 });
  }
  const ctx = document.createElement("canvas").getContext("2d");
  const wide = (str, font, gap = 0) => {
    if (ctx) ctx.font = font;
    return Math.ceil((ctx ? ctx.measureText(str).width : str.length * 8) + gap * str.length) + 2;
  };
  const boxes = [];
  const fixed = (bx, by, str, a, size, font, gap) => {
    const w = wide(str, font, gap), anchor = a["text-anchor"];
    txt(svg, bx, by, str, a);
    boxes.push([anchor === "end" ? bx - w : anchor === "middle" ? bx - w / 2 : bx, by - size, w, size + 3]);
  };
  const title = { "font-weight": 600, "letter-spacing": "1.5" }, titleFont = "600 12px Barlow, sans-serif";
  fixed((L + W - R) / 2, H - 8, names[1]?.[1] ?? "", Object.assign({ "text-anchor": "middle" }, title), 12, titleFont, 1.5);
  fixed(L + 6, T + 12, names[2]?.[1] ?? "", title, 12, titleFont, 1.5);
  const corner = { "fill-opacity": 0.45, "font-size": 11, "letter-spacing": "1.2" }, cornerFont = "11px Barlow, sans-serif";
  const end = Object.assign({ "text-anchor": "end" }, corner);
  fixed(W - R - 6, T + 12, "LOOSE · AGGRESSIVE", end, 11, cornerFont, 1.2);
  fixed(W - R - 6, y(0) - 8, "LOOSE · PASSIVE", end, 11, cornerFont, 1.2);
  fixed(L + 44, T + 12, "TIGHT · AGGRESSIVE", corner, 11, cornerFont, 1.2);
  fixed(L + 6, y(0) - 8, "TIGHT · PASSIVE", corner, 11, cornerFont, 1.2);
  const wt = pts.reduce((s, p) => s + (p.w || 0), 0);
  const avg = (key) => (wt ? pts.reduce((s, p) => s + p[key] * (p.w || 0), 0) / wt : pts.reduce((s, p) => s + p[key], 0) / pts.length);
  const mx = avg("x"), my = avg("y"), dash = { stroke: css("--chalk"), "stroke-opacity": 0.4, "stroke-dasharray": "5 4", "stroke-width": 1.2 };
  svg.append(sv("line", Object.assign({ x1: x(mx), x2: x(mx), y1: T, y2: y(0) }, dash)), sv("line", Object.assign({ x1: L, x2: W - R, y1: y(my), y2: y(my) }, dash)));
  const tagA = { "fill-opacity": 0.55, "font-size": 10 }, tagFont = "10px Barlow, sans-serif", tags = boxes.length;
  const vTag = `club avg ${Math.round(mx)}%`, vFits = x(mx) + 5 + wide(vTag, tagFont) <= W - R;
  fixed(vFits ? x(mx) + 5 : x(mx) - 5, T + 28, vTag, Object.assign({ "text-anchor": vFits ? "start" : "end" }, tagA), 10, tagFont);
  fixed(W - R - 4, y(my) - 5, `club avg ${Math.round(my)}%`, Object.assign({ "text-anchor": "end" }, tagA), 10, tagFont);
  const tagBoxes = boxes.slice(tags);
  boxes.push(...pts.map((p) => [x(p.x) - 7, y(p.y) - 7, 14, 14]));
  const nameFont = "600 13px Barlow, sans-serif", nameAttrs = { "font-weight": 600, "font-size": 13 };
  const hit = (a, b) => a[0] < b[0] + b[2] + 2 && b[0] < a[0] + a[2] + 2 && a[1] < b[1] + b[3] + 1 && b[1] < a[1] + a[3] + 1;
  const inside = (b) => b[0] >= L && b[0] + b[2] <= W - 2 && b[1] >= 0 && b[1] + b[3] <= y(0) + 3;
  const around = (cx, cy, w) => [[cx + 10, cy - 8], [cx - 10 - w, cy - 8], [cx - w / 2, cy - 23], [cx - w / 2, cy + 8]]
    .map(([bx, by]) => [bx, by, w, 15]);
  let tip = null, owner = null;
  const hide = (e) => {
    if (e && e.target === owner) return;
    tip?.remove();
    tip = owner = null;
    document.removeEventListener("click", hide);
  };
  const show = (dot, name, cx, cy) => {
    hide();
    const w = wide(name, nameFont), cand = around(cx, cy, w);
    const b = cand.find((c) => inside(c) && !tagBoxes.some((t) => hit(c, t))) ?? cand.find(inside) ?? cand[0];
    const bx = Math.min(Math.max(b[0], 2), W - 2 - w);
    tip = sv("g", { class: "tip" });
    tip.append(sv("rect", { x: bx - 4, y: b[1] - 2, width: w + 8, height: b[3] + 4, fill: css("--board"), stroke: css("--board-line") }));
    tip.append(sv("text", Object.assign({ x: bx, y: b[1] + 12, fill: css("--chalk"), "font-family": "Barlow, sans-serif" }, nameAttrs), name));
    svg.append(tip);
    owner = dot;
    document.addEventListener("click", hide);
  };
  const unnamed = [];
  const spots = pts.map((p) => {
    const cx = x(p.x), cy = y(p.y);
    const spot = around(cx, cy, wide(p.name, nameFont)).find((b) => inside(b) && !boxes.some((o) => hit(b, o)));
    if (spot) boxes.push(spot);
    const dot = sv("circle", { cx, cy, r: 6, fill: css("--ball") });
    if (!spot) {
      unnamed.push({ name: p.name, cx, cy });
      dot.append(sv("title", {}, p.name));
      dot.setAttribute("class", "tap");
      dot.addEventListener("click", () => {
        const stack = unnamed.filter((o) => Math.hypot(o.cx - cx, o.cy - cy) < 12).map((o) => o.name);
        show(dot, [p.name, ...stack.filter((n) => n !== p.name)].join(" · "), cx, cy);
      });
    }
    svg.append(dot);
    return spot;
  });
  pts.forEach((p, i) => { if (spots[i]) txt(svg, spots[i][0], spots[i][1] + 12, p.name, nameAttrs); });
  return svg;
}

function playerChart(cs, mode, logged) {
  const W = chartW(716), H = 260, L = 56, R = 16, T = 22, B = 30, n = cs.length;
  const all = cs.flatMap((c) => [c.high, c.low, c.close - c.open]).concat(0);
  const { lo, hi, step } = scale(Math.min(...all), Math.max(...all), 4);
  const y = (v) => T + (H - T - B) * (hi - v) / (hi - lo), slot = (W - L - R) / n, X = (i) => L + slot * i + slot / 2;
  const svg = svgBox(W, H), show = labelAt(n), vals = n <= (narrow() ? 8 : 16);
  for (let v = lo; v <= hi + 1e-9; v += step) {
    gridLine(svg, L, W - R, y(v), Math.abs(v) < 1e-9);
    txt(svg, L - 8, y(v) + 4, fmt(v), { "text-anchor": "end", "fill-opacity": 0.7 });
  }
  cs.forEach((c, i) => { if (show(i)) txt(svg, X(i), H - 9, shortLabel(c.date), { "text-anchor": "middle", "fill-opacity": 0.7 }); });
  const marks = [], line = mode === "line";
  if (line) {
    cs.forEach((c, i) => {
      const dv = c.close - c.open, top = Math.min(y(dv), y(0)), h = Math.max(2, Math.abs(y(dv) - y(0)));
      marks.push(sv("rect", { class: "mark dbar", x: X(i) - slot / 2 + Math.min(8, slot / 6), y: top, width: Math.max(2, slot - 2 * Math.min(8, slot / 6)),
        height: h, fill: css(dv >= 0 ? "--up" : "--down"), "fill-opacity": 0.35 }));
      svg.append(marks[i]);
      if (vals) txt(svg, X(i), dv >= 0 ? top - 5 : top + h + 13, fmt(dv), { "text-anchor": "middle", "font-weight": 600, "font-size": 11, "fill-opacity": 0.85 });
    });
    svg.append(sv("polyline", { points: cs.map((c, i) => `${X(i)},${y(c.close)}`).join(" "), fill: "none", stroke: css("--ball"), "stroke-width": 3, "stroke-linejoin": "round" }));
    svg.append(sv("circle", { cx: X(n - 1), cy: y(cs[n - 1].close), r: 5, fill: css("--ball") }));
  } else {
    cs.forEach((c, i) => {
      const col = css(c.close >= c.open ? "--up" : "--down"), top = Math.min(y(c.close), y(c.open));
      const h = Math.max(2, Math.abs(y(c.close) - y(c.open))), bw = Math.max(2, slot - 4), g = sv("g", { class: "mark" });
      g.append(sv("line", { x1: X(i), x2: X(i), y1: y(c.high), y2: y(c.low), stroke: col, "stroke-width": 2 }));
      g.append(sv("rect", { x: X(i) - bw / 2, y: top, width: bw, height: h, fill: col }));
      svg.append(g);
      marks.push(g);
      if (vals) txt(svg, X(i), y(c.high) - 6, fmt(c.close - c.open), { "text-anchor": "middle", "font-weight": 600 });
    });
  }
  hoverLayer(svg, cs.map((c) => c.date), X, L, T, (i, { gx, layer }) => {
    const c = cs[i], dv = r6(c.close - c.open);
    layer.append(sv("line", { x1: gx, x2: gx, y1: T, y2: H - B, stroke: css("--chalk"), "stroke-opacity": 0.55, "stroke-dasharray": "3 3" }));
    if (line) layer.append(sv("circle", { cx: gx, cy: y(c.close), r: 5.5, fill: css("--ball"), stroke: css("--board"), "stroke-width": 1.5 }));
    return { node: marks[i], nodes: [el("div", { class: "facts" }, tagChip(c.tag), el("span", { class: "res " + tone(dv) }, pnlParts(dv)),
      el("span", { class: "sub" }, `${fmt(c.open)} → ${fmt(c.close)}`),
      logged?.[i] ? el("span", { class: "sub" }, `high ${fmt(c.high)} / low ${fmt(c.low)}`) : null)] };
  });
  return svg;
}

function recordsNode(d, R) {
  const tile = (label, c, value, cls, cap, person = c?.person) => el("div", {}, el("i", {}, label),
    c ? [el("b", { class: cls || null }, value), person != null ? who(d, person) : null, cap ? el("u", {}, cap) : null] : el("b", {}, "–"));
  const span = (c) => (c.from === c.date ? dayLabel(c.date) : `${shortLabel(c.from)} to ${shortLabel(c.date)}`);
  const times = (v) => (v === 1 ? "once" : v === 2 ? "twice" : `${v} times`);
  const m = (v) => `${v} ${v === 1 ? "match" : "matches"}`;
  const { bestDay: a, worstDay: b, winRun: c, loseRun: e, mostTops: f, mostMatches: g, comeback: k, busiest: u, downswing: w, peak: p } = R;
  return el("div", { class: "rec" },
    tile("Best single day", a, a && fmt(a.value), a && tone(a.value), a && dayLabel(a.date)),
    tile("Worst single day", b, b && fmt(b.value), b && tone(b.value), b && dayLabel(b.date)),
    tile("Longest winning run", c, c && m(c.value), "", c && span(c)),
    tile("Longest losing run", e, e && m(e.value), "", e && span(e)),
    tile("Most match day wins", f, f && f.value, "", f && `top of the match day ${times(f.value)}`),
    tile("Most matches", g, g && g.value, "", null),
    tile("Biggest comeback", k, k && fmt(k.value), "up", k && `${fmt(k.low)} → ${fmt(k.end)} on ${shortLabel(k.date)}`),
    tile("Busiest match day", u, u && `${u.value} players`, "", u && `${dayLabel(u.date)} · ${num(u.total)} balls in`, null),
    tile("Biggest downswing", w, w && fmt(w.value), "down", w && span(w)),
    tile("Highest peak", p, p && fmt(p.value), tone(p?.value ?? 0), p && dayLabel(p.date)));
}

function h2hNode(d, period) {
  const { people, wins } = headToHead(d, period);
  const head = el("tr", {}, el("th", {}, ""), people.map((p) => el("th", {}, nameOf(d, p))));
  const rows = people.map((a) => el("tr", {}, el("td", {}, el("a", { href: "#player-" + a }, nameOf(d, a))), people.map((b) => {
    if (a === b) return el("td", { class: "self" }, "·");
    const x = wins[`${a}-${b}`], y = wins[`${b}-${a}`];
    return el("td", { class: x > y ? "up" : x < y ? "down" : null }, `${x}–${y}`);
  })));
  return el("table", { class: "h2h" }, head, rows);
}

function advNode(d, period) {
  const rows = advanced(d, period), labels = d.labels?.adv ?? [];
  const pctKeys = new Set(labels.slice(1, 5).map((a) => a[0]));
  const head = el("tr", {}, el("th", {}, "Player"), labels.map((a) => el("th", {}, a[1])));
  const body = rows.map((r) => el("tr", {}, el("td", {}, el("a", { href: "#player-" + r.person }, r.name)),
    labels.map(([k]) => el("td", {}, pctKeys.has(k) ? r[k] + "%" : num(r[k])))));
  return rows.length ? el("div", { class: "scrollx" }, el("table", { class: "adv" }, head, body)) : null;
}

function ladderView() {
  const { d, period } = S, rows = ladder(d, period);
  const sw = el("div", { class: "period", role: "group" }, [["all", "All time"], ["month", "Month"], ["week", "Week"]].map(([k, t]) =>
    el("button", { type: "button", class: k === period ? "on" : null, "aria-pressed": String(k === period), onclick: () => { S.period = k; draw(); } }, t)));
  const out = [el("div", { class: "headrow" }, el("h1", { class: "title" }, "The ladder"), sw)];
  if (!rows.length) return out.concat(el("p", { class: "empty" }, message("empty")));
  const head = el("div", { class: "row head" }, el("div", { class: "rk" }, "#"), el("div", {}, "Player"), el("div", {}, "Form"),
    el("div", { class: "num wide" }, "Matches"), el("div", { class: "num wide" }, "Win"),
    el("div", { class: "pnlh" }, el("span", { class: "pnl" }, ballmark(), "PnL")), el("div", {}, ""));
  const shown = S.showAll ? rows : rows.slice(0, 10);
  out.push(el("div", { class: "sb", onpointerdown: press }, head, shown.map((r) => el("a", { class: "row link" + (r.rank === 1 ? " r1" : ""), href: "#player-" + r.person },
    el("div", { class: "rk" }, r.rank), el("div", { class: "nm" }, r.name), formNode(form(d, r.person, 5, period), 5),
    el("div", { class: "num wide" }, r.matches), el("div", { class: "num wide" }, Math.round(100 * r.wins / r.matches) + "%"),
    el("div", { class: "tot " + tone(r.total) }, pnlParts(r.total)), chev()))));
  if (rows.length > 10 && !S.showAll) {
    out.push(el("div", { class: "pager" }, el("button", { type: "button", onclick: () => { S.showAll = true; draw(); } }, `Show all ${rows.length} ▾`),
      el("em", {}, "Top 10 shown")));
  }
  const pts = stylePoints(d, period), adv = advNode(d, period);
  out.push(el("h2", { class: "sec" }, "Season race"), el("div", { class: "chart" }, raceChart(d, period, rows)),
    el("h2", { class: "sec" }, "Rank over time"), el("div", { class: "chart" }, rankChart(d, period, rows)),
    el("h2", { class: "sec" }, "Records"), recordsNode(d, records(d, period)),
    el("h2", { class: "sec" }, "Head to head"), el("div", { class: "scrollx" }, h2hNode(d, period)),
    el("div", { class: "note" }, "Read across: the first number is the matches the row player finished above the column player, out of the matches both played."),
    el("h2", { class: "sec" }, "Club activity"), el("div", { class: "chart" }, activityChart(activity(d, period), inPeriod(d, period))),
    el("div", { class: "note" }, "Balls in play per match day. Green is a home day, yellow is an online day."),
    el("h2", { class: "sec" }, "Advanced"), adv,
    el("div", { class: "note" }, adv ? "From online days that have a full log. Home days have none." : "No online day in this period has a full log yet."));
  if (pts.length) out.push(el("div", { class: "kicker" }, "Style map"), el("div", { class: "chart" }, styleChart(d, pts)));
  return out;
}

function detailNode(md) {
  const rows = detail(md, S.d), online = md.tag === "online";
  const head = el("tr", {}, el("th", {}, "Player"), online ? el("th", { class: "hcol" }, "Name") : null,
    el("th", {}, "Balls in"), el("th", {}, "Balls out"), el("th", {}, ballmark(), "PnL"));
  return el("div", { class: "detail" }, el("table", {}, head, rows.map((r) => el("tr", {},
    el("td", {}, el("a", { href: "#player-" + r.person }, r.name)),
    online ? el("td", { class: "hcol" }, r.handle != null ? el("span", { class: "hn" }, r.handle) : "") : null,
    el("td", {}, num(r.in)), el("td", {}, num(r.out)), el("td", { class: tone(r.net) || null }, fmt(r.net))))));
}

function historyView(focusN) {
  const rows = matchdayRows(S.d, "all"), byN = new Map(S.d.matchdays.map((m) => [m.n, m]));
  if (focusN != null) S.open.add(focusN);
  const out = [el("div", { class: "kicker" }, "Newest first"), el("h1", { class: "title" }, "History")];
  if (!rows.length) return out.concat(el("p", { class: "empty" }, message("empty")));
  const list = el("div", { class: "sb" });
  for (const r of rows) {
    const md = byN.get(r.n);
    let open = S.open.has(r.n), box = open ? detailNode(md) : null;
    const row = el("button", { type: "button", class: "md" + (open ? " open" : ""), "aria-expanded": String(open), "data-n": r.n },
      el("span", { class: "d" }, dayLabel(r.date)), tagChip(r.tag), el("span", { class: "p" }, `${r.players} players`),
      el("span", { class: "w " + tone(r.topNet) }, `${r.topName} `, pnlParts(r.topNet)));
    row.addEventListener("click", () => {
      open = !open;
      row.classList.toggle("open", open);
      row.setAttribute("aria-expanded", String(open));
      if (open) { S.open.add(r.n); box = detailNode(md); row.after(box); } else { S.open.delete(r.n); box?.remove(); box = null; }
    });
    list.append(row);
    if (box) list.append(box);
  }
  return out.concat(list);
}

function playerView(person) {
  const d = S.d, row = ladder(d, "all").find((r) => r.person === person), st = stats(d, person), cs = candles(d, person);
  const mine = d.matchdays.filter((m) => m.players.some((p) => p.person === person));
  const online = mine.filter((m) => m.tag === "online").length, won = Math.round(st.winRate * st.played / 100);
  const logged = mine.map((m) => !!m.players.find((p) => p.person === person)?.adv);
  const chartBox = el("div", { class: "chart" }, playerChart(cs, S.mode, logged));
  const sw = el("div", { class: "period", role: "group" }, [["candle", "Candles"], ["line", "Line"]].map(([k, t]) =>
    el("button", { type: "button", class: k === S.mode ? "on" : null, "data-m": k }, t)));
  sw.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    S.mode = b.dataset.m;
    for (const n of sw.children) n.classList.toggle("on", n === b);
    chartBox.replaceChildren(playerChart(cs, S.mode, logged));
  });
  const rowsNode = mine.slice().reverse().map((m) => {
    const p = m.players.find((q) => q.person === person);
    return el("a", { class: "md link", href: "#history-" + m.n }, el("span", { class: "d" }, dayLabel(m.date)), tagChip(m.tag),
      el("span", { class: "p" }, p.handle != null ? el("span", { class: "hn" }, p.handle) : null, p.device != null ? el("span", { class: "dev" }, p.device) : null),
      el("span", { class: "w " + tone(p.net) }, pnlParts(p.net)), chev());
  });
  return [
    el("a", { class: "back", href: "#ladder" }, `‹ Ladder · rank ${row.rank}`),
    el("div", { class: "hero" }, el("h1", { class: "title" }, row.name), el("div", { class: "big " + tone(row.total) }, fmt(row.total), ballmark()),
      formNode(form(d, person, 7), 7)),
    el("div", { class: "tiles" },
      el("div", { class: "tile" }, el("i", {}, "Matches"), el("b", {}, st.played), el("u", {}, `${online} online · ${st.played - online} home`)),
      el("div", { class: "tile" }, el("i", {}, "Win rate"), el("b", {}, st.winRate + "%"), el("u", {}, `${won} of ${st.played} ended up`)),
      el("div", { class: "tile" }, el("i", {}, "Best day"), el("b", { class: tone(st.best.net) || null }, fmt(st.best.net)), el("u", {}, dayLabel(st.best.date))),
      el("div", { class: "tile" }, el("i", {}, "Worst day"), el("b", { class: tone(st.worst.net) || null }, fmt(st.worst.net)), el("u", {}, dayLabel(st.worst.date)))),
    el("div", { class: "headrow mini" }, el("div", { class: "kicker" }, "PnL"), sw),
    chartBox,
    el("div", { class: "kicker", style: "margin-top:16px" }, "Match days"),
    el("div", { class: "sb", onpointerdown: press }, rowsNode),
  ];
}

function seatName(h, k) {
  const s = h.seats?.[k];
  if (!s) return "";
  return s.person != null && S.d.people?.[String(s.person)] ? nameOf(S.d, s.person) : String(s.handle ?? "");
}

function summary(h) {
  const w = seatName(h, h.winner), tot = num(h.collected), acts = h.actions ?? [];
  if (h.kind === "smash") {
    const n = new Set(acts.filter((a) => a.w === "smashes").map((a) => a.seat)).size;
    return `Most smashes · ${n} ${n === 1 ? "player" : "players"} smashed. ${w} took ${tot}.`;
  }
  if (h.kind === "fake") return `Best fake · ${w} served, the rest let it go, and ${w} took ${tot}.`;
  if (h.kind === "return") {
    const hit = acts.filter((a) => a.seat !== h.winner && (a.w === "serves" || a.w === "smashes") && a.street > 0).pop();
    if (hit) return `Best return · ${w} returned a ${hit.w === "smashes" ? "smash" : "serve"} of ${num(hit.to ?? hit.add)} and took ${tot}.`;
    return `Best return · ${w} took ${tot}.`;
  }
  return `Biggest rally · ${w} took ${tot}.`;
}

function sentence(h, f, prev) {
  const nm = seatName(h, f.seat), len = f.board.length, was = prev ? prev.board.length : 0;
  let pre = "";
  if (len > was) pre = was === 0 && len === 3 ? "Three balls land. " : len - was === 1 ? (len === 4 ? "Fourth ball. " : "Last ball. ") : "The rest of the balls land. ";
  const said = {
    serves: `${nm} serves ${num(f.add)}.`, returns: f.add ? `${nm} returns ${num(f.add)}.` : `${nm} returns.`,
    waits: `${nm} waits.`, "lets it go": `${nm} lets it go.`, smashes: `${nm} smashes for ${num(f.to ?? f.add)}.`,
    wins: `${nm} wins ${num(f.total)}.`,
  };
  return pre + (said[f.w] ?? `${nm} ${f.w}.`);
}

function stageNode(h, md) {
  const fr = frames(h), suits = S.d.labels?.suits ?? [], board = (h.board ?? []).slice(0, 5);
  const ball = (c, cls) => {
    if (!c) return el("div", { class: "pc " + cls });
    const s = Number(c[1]);
    return el("div", { class: `pc c${s}` }, String(c[0]), el("i", { class: `s${s}` }, suits[s] ?? ""));
  };
  const boardBox = el("div", { class: "balls" }), totalEl = el("span"), seatsBox = el("div", { class: "seats" });
  const ticker = el("div", { class: "ticker", "aria-live": "polite" }), barI = el("i"), cnt = el("span", { class: "cnt" });
  const play = el("button", { type: "button", class: "play" }, "▶ Play");
  const back = el("button", { type: "button", "aria-label": "Back" }, "‹"), next = el("button", { type: "button", "aria-label": "Next" }, "›");
  let i = 0, timer = null;
  const paint = () => {
    const f = fr[i];
    if (!f) return;
    const last = i === fr.length - 1;
    boardBox.replaceChildren(...Array.from({ length: 5 }, (_, k) => (k < f.board.length ? ball(f.board[k]) : ball(null, "empty"))));
    totalEl.textContent = num(f.total);
    seatsBox.replaceChildren(...(h.seats ?? []).map((s, k) => {
      const out = f.out.includes(k), win = (last || f.w === "wins") && h.winner === k, act = f.seat === k;
      const mine = f.shown[String(k)];
      const status = el("div", { class: "st" });
      if (out) status.append("Out");
      else if (win) status.append("Wins", ballmark(), num(h.collected));
      else if (f.put[k] != null) {
        const word = act ? { serves: "Serve", returns: "Return", smashes: "Smash" }[f.w] : null;
        if (word) status.append(word);
        status.append(ballmark(), num(f.put[k]));
      }
      return el("div", { class: "seat" + (out ? " out" : "") + (win ? " win" : act ? " act" : "") },
        el("div", { class: "nm" }, seatName(h, k)),
        s.handle != null ? el("div", { class: "hd" }, el("span", { class: "as" }, "as"), el("span", { class: "hn" }, s.handle)) : null,
        el("div", { class: "balls" }, mine ? mine.map((c) => ball(c)) : [ball(null, "back"), ball(null, "back")]), status);
    }));
    ticker.textContent = sentence(h, f, fr[i - 1]);
    barI.style.width = (fr.length > 1 ? 100 * i / (fr.length - 1) : 100) + "%";
    cnt.textContent = `${i + 1} of ${fr.length}`;
  };
  const stop = () => { clearInterval(timer); timer = null; play.textContent = "▶ Play"; };
  play.addEventListener("click", () => {
    if (timer) return stop();
    if (i === fr.length - 1) i = 0;
    paint();
    play.textContent = "❚❚ Pause";
    timer = setInterval(() => { if (i < fr.length - 1) { i++; paint(); } if (i === fr.length - 1) stop(); }, 1100);
  });
  next.addEventListener("click", () => { stop(); if (i < fr.length - 1) i++; paint(); });
  back.addEventListener("click", () => { stop(); if (i > 0) i--; paint(); });
  S.stop = stop;
  paint();
  const meta = el("div", { class: "hlmeta" }, el("b", {}, dayLabel(md.date)), tagChip(md.tag), el("b", {}, `Rally ${h.hand}${h.of ? " of " + h.of : ""}`));
  return el("div", { class: "stage" },
    el("div", { class: "court" }, meta, boardBox, el("div", { class: "take" }, ballmark(), totalEl)),
    seatsBox, ticker, el("div", { class: "hlsum" }, summary(h)),
    el("div", { class: "ctl" }, play, back, next, el("div", { class: "bar" }, barI), cnt));
}

function highlightsView() {
  const pools = {}, where = new Map();
  for (const m of S.d.matchdays) for (const h of m.highlights ?? []) { (pools[h.kind] ||= []).push(h); where.set(h, m); }
  const kinds = KINDS.filter(([k]) => pools[k]?.length);
  const out = [el("h1", { class: "title" }, "Highlights")];
  if (!kinds.length) return out.concat(el("p", { class: "empty" }, message("nohl")));
  if (!S.hl || !pools[S.hl.kind]) S.hl = { kind: kinds[0][0], h: choose(pools[kinds[0][0]], Math.random(), null) };
  const go = (kind, last) => { S.stop(); S.hl = { kind, h: choose(pools[kind], Math.random(), last) }; draw(); };
  out.push(el("div", { class: "hl-tabs" }, kinds.map(([k, t]) =>
    el("button", { type: "button", class: k === S.hl.kind ? "on" : null, onclick: () => go(k, S.hl.kind === k ? S.hl.h : null) }, t)),
  el("button", { type: "button", onclick: () => go(S.hl.kind, S.hl.h) }, "Shuffle ↻")));
  out.push(stageNode(S.hl.h, where.get(S.hl.h)));
  return out;
}

function draw() {
  let v = route(location.hash);
  const person = v.startsWith("player-") ? Number(v.slice(7)) : null;
  if (person != null && !ladder(S.d, "all").some((r) => r.person === person)) v = "ladder";
  let focusN = v.startsWith("history-") ? Number(v.slice(8)) : null;
  if (focusN != null && !S.d.matchdays.some((m) => m.n === focusN)) { v = "history"; focusN = null; }
  const changed = v !== S.view;
  if (changed && v === "highlights") S.hl = null;
  S.stop();
  S.stop = () => {};
  S.view = v;
  const tab = v.startsWith("player-") ? "ladder" : v.startsWith("history") ? "history" : v;
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("on", a.dataset.v === tab);
  const view = document.getElementById("view");
  const nodes = tab === "history" ? historyView(focusN) : v === "highlights" ? highlightsView() : v.startsWith("player-") ? playerView(person) : ladderView();
  view.replaceChildren(...nodes.filter(Boolean));
  if (changed) window.scrollTo(0, 0);
  if (changed && focusN != null) view.querySelector(`.md[data-n="${focusN}"]`)?.scrollIntoView({ block: "start" });
}

function themeMenu() {
  const root = document.documentElement, btn = document.getElementById("tbtn"), pop = document.getElementById("tpop");
  const mark = () => { for (const b of pop.querySelectorAll("button")) b.classList.toggle("on", root.dataset[b.dataset.k] === b.dataset.v); };
  const show = (on) => { pop.hidden = !on; btn.setAttribute("aria-expanded", String(on)); };
  btn.addEventListener("click", (e) => { e.stopPropagation(); show(pop.hidden); });
  pop.addEventListener("click", (e) => {
    e.stopPropagation();
    const b = e.target.closest("button");
    if (!b) return;
    root.dataset[b.dataset.k] = b.dataset.v;
    try { localStorage.setItem(b.dataset.k, b.dataset.v); } catch { }
    mark();
  });
  document.addEventListener("click", () => show(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") show(false); });
  mark();
}

function start(d) {
  S.d = d;
  draw();
  const u = document.getElementById("upd");
  if (isDay(d.updated)) u.append("Updated ", el("b", {}, dayLabel(d.updated).slice(0, 3)), " " + shortLabel(d.updated));
  document.getElementById("gate").remove();
  document.getElementById("app").hidden = false;
  themeMenu();
  addEventListener("hashchange", draw);
  matchMedia("(max-width: 600px)").addEventListener("change", draw);
}

function boot() {
  const formEl = document.getElementById("gate-form"), pw = document.getElementById("pw");
  const err = document.getElementById("err"), go = document.getElementById("go");
  const fetchData = () => fetch("data.bin", { cache: "no-store" }).then((r) => {
    if (!r.ok) throw new Error(MSG.load);
    return r.arrayBuffer();
  });
  let pending = fetchData();
  pending.catch(() => { pending = null; });
  let busy = false;
  formEl.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy) return;
    busy = true;
    go.disabled = true;
    err.textContent = "";
    const typed = pw.value.trim();
    let bytes = null;
    try {
      pending ||= fetchData();
      bytes = await pending;
    } catch {
      pending = null;
      err.textContent = message("load");
    }
    let d = null;
    if (bytes) {
      try {
        d = await decrypt(bytes, typed);
      } catch {
        err.textContent = message("wrong");
        pw.select();
      }
    }
    if (d) {
      try {
        start(d);
        return;
      } catch {
        err.textContent = message("load");
      }
    }
    busy = false;
    go.disabled = false;
  });
}

if (typeof document !== "undefined") boot();

"""IoT Edge DDoS Perception Dashboard — Raspberry Pi friendly (stdlib only).

Pairs with live_detector.py:
  reads  reports/detector_state.json   (KPIs, per-IP threat table, telemetry)
         reports/monitor_events.jsonl  (incremental packet/window/action stream)
         reports/model_comparison_report.json (benchmark table)
  writes reports/control_commands.json (Block/Release buttons from the UI)

Serve on the Pi:  python3 monitor_dashboard.py --port 8080
Open on laptop:   http://<raspberry-pi-ip>:8080
"""

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fuzzy Edge Monitor — IoT Flood Detection</title>
<style>
  :root {
    --bg: #f5f6f8;
    --card: #ffffff;
    --line: #e9ecf1;
    --txt: #101828;
    --muted: #667085;
    --faint: #98a2b3;
    --blue: #2563eb;
    --blue-soft: #eff6ff;
    --green: #16a34a;
    --green-soft: #ecfdf5;
    --orange: #ea8a0c;
    --orange-soft: #fff7ed;
    --red: #dc2626;
    --red-soft: #fef2f2;

    /* motion tokens */
    --ease-out: cubic-bezier(0.22, 1, 0.36, 1);
    --ease-spring: cubic-bezier(0.34, 1.4, 0.64, 1);
    --dur-fast: 150ms;
    --dur: 260ms;
    --dur-slow: 480ms;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI",
                 Roboto, "Helvetica Neue", Arial, sans-serif;
    margin: 0; background: var(--bg); color: var(--txt);
    font-size: 14px; line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  /* ---------- header ---------- */
  header.topbar {
    position: sticky; top: 0; z-index: 50;
    background: rgba(255,255,255,.72);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    backdrop-filter: blur(20px) saturate(180%);
    border-bottom: 1px solid transparent;
    transition: border-color var(--dur) var(--ease-out), box-shadow var(--dur) var(--ease-out);
  }
  header.topbar.scrolled {
    border-bottom-color: rgba(16,24,40,.06);
    box-shadow: 0 1px 12px rgba(16,24,40,.05);
  }
  .topbar-inner {
    max-width: 1280px; margin: 0 auto; padding: 12px 24px;
    display: flex; align-items: center; gap: 14px;
  }
  .logo {
    width: 40px; height: 40px; border-radius: 12px; flex: none;
    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
    display: grid; place-items: center; color: #fff;
    box-shadow: 0 2px 8px rgba(37,99,235,.35);
  }
  .titles h1 { font-size: 16px; font-weight: 700; letter-spacing: -0.01em; margin: 0; }
  .titles p { margin: 0; font-size: 12.5px; color: var(--muted); }
  .spacer { flex: 1; }

  .pill {
    display: inline-flex; align-items: center; gap: 7px;
    background: var(--card); border: 1px solid var(--line); border-radius: 999px;
    padding: 6px 14px; font-size: 13px; font-weight: 600; color: var(--muted);
    transition: border-color var(--dur) var(--ease-out), color var(--dur) var(--ease-out);
  }
  .pill .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--faint); flex: none; }
  .pill.live .dot { background: var(--green); animation: breathe 2s var(--ease-out) infinite; }
  .pill.live { color: var(--green); border-color: #d1fae5; }
  .pill.down .dot { background: var(--red); }
  .pill.down { color: var(--red); border-color: #fee2e2; }
  .pill.wait .dot { background: var(--orange); }
  .pill.wait { color: var(--orange); border-color: #ffedd5; }
  @keyframes breathe { 50% { opacity: .35; } }

  .statechip {
    display: inline-flex; align-items: center; border-radius: 999px;
    padding: 6px 14px; font-size: 13px; font-weight: 700; letter-spacing: .2px;
    transition: background var(--dur) var(--ease-out), color var(--dur) var(--ease-out);
  }
  .statechip.CLEAR    { background: var(--green-soft); color: var(--green); }
  .statechip.ELEVATED { background: var(--orange-soft); color: var(--orange); }
  .statechip.ATTACK   { background: var(--red-soft); color: var(--red); animation: breathe 1.4s var(--ease-out) infinite; }
  .statechip.WAIT     { background: #f2f4f7; color: var(--muted); }

  .btn {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--card); border: 1px solid var(--line); color: var(--txt);
    border-radius: 10px; padding: 7px 14px; font-size: 13px; font-weight: 600;
    cursor: pointer; font-family: inherit;
    transition: transform var(--dur-fast) var(--ease-out),
                background var(--dur-fast) var(--ease-out),
                border-color var(--dur-fast) var(--ease-out),
                box-shadow var(--dur-fast) var(--ease-out);
  }
  .btn:hover { border-color: #d0d5dd; background: #fcfcfd; }
  .btn:active { transform: scale(.97); }
  .btn.danger { color: var(--red); border-color: #fee2e2; background: var(--red-soft); }
  .btn.mini { padding: 4px 10px; font-size: 12px; border-radius: 8px; }

  /* ---------- layout ---------- */
  main { max-width: 1280px; margin: 0 auto; padding: 20px 24px 60px; }
  .grid { display: grid; gap: 16px; }
  .kpis { grid-template-columns: repeat(6, 1fr); }
  .duo { grid-template-columns: 1fr 1fr; }

  section.card {
    background: var(--card); border: 1px solid var(--line); border-radius: 16px;
    padding: 18px 20px;
    box-shadow: 0 1px 2px rgba(16,24,40,.04);
    opacity: 0; transform: translateY(10px);
    animation: rise var(--dur-slow) var(--ease-out) forwards;
    animation-delay: calc(var(--i, 0) * 55ms);
  }
  @keyframes rise { to { opacity: 1; transform: none; } }

  .card .t { font-size: 12.5px; font-weight: 600; color: var(--muted); letter-spacing: 0; }
  .card .v {
    font-size: 27px; font-weight: 700; letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums; line-height: 1.15; margin-top: 4px;
    transition: color var(--dur) var(--ease-out);
  }
  .card .s { font-size: 12px; color: var(--faint); margin-top: 5px; min-height: 16px; }
  .v.ok { color: var(--green); } .v.warn { color: var(--orange); } .v.bad { color: var(--red); }
  .v.blue { color: var(--blue); }
  .kpi-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
  .kpi-ico {
    width: 34px; height: 34px; border-radius: 10px; flex: none;
    display: grid; place-items: center;
  }
  .kpi-ico.blue   { background: var(--blue-soft);   color: var(--blue); }
  .kpi-ico.green  { background: var(--green-soft);  color: var(--green); }
  .kpi-ico.orange { background: var(--orange-soft); color: var(--orange); }
  .kpi-ico.red    { background: var(--red-soft);    color: var(--red); }
  .sub b.green { color: var(--green); font-weight: 600; }
  .sub b.red { color: var(--red); font-weight: 600; }

  h2.sect { font-size: 21px; font-weight: 700; letter-spacing: -0.02em; margin: 30px 0 14px; }
  section.card h3 {
    margin: 0 0 4px; font-size: 16px; font-weight: 700; letter-spacing: -0.01em;
    display: flex; align-items: center; gap: 10px;
  }
  section.card h3 small { color: var(--muted); font-weight: 500; font-size: 12.5px; }
  section.card h3 .hbtn { margin-left: auto; }
  .card .desc { color: var(--muted); font-size: 12.5px; margin: 0 0 12px; }

  /* ---------- charts & explain ---------- */
  .chart-wrap { position: relative; height: 200px; margin-top: 10px; }
  canvas { width: 100%; height: 100%; display: block; }
  .legend { display: flex; gap: 16px; font-size: 12px; color: var(--muted); margin-top: 10px; }
  .dot-s { display: inline-block; width: 9px; height: 9px; border-radius: 3px; margin-right: 5px; vertical-align: -1px; }

  .verdictline { display: flex; align-items: baseline; gap: 10px; margin: 6px 0 12px; }
  .verdictline .big { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; }
  .verdictline .mutedline { color: var(--muted); font-size: 12.5px; }
  .rule { margin: 10px 0; }
  .rule .lbl { display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 4px; }
  .rule .lbl b { font-variant-numeric: tabular-nums; font-weight: 600; }
  .rule .bar { height: 7px; background: #f1f3f7; border-radius: 4px; overflow: hidden; }
  .rule .bar i {
    display: block; height: 100%; border-radius: 4px;
    background: linear-gradient(90deg, #fbbf24, #ef4444);
    transition: width var(--dur-slow) var(--ease-out);
  }
  .muted { color: var(--muted); }
  .footnote { font-size: 11.5px; color: var(--faint); margin-top: 10px; }

  /* ---------- tables ---------- */
  .scrollwrap { position: relative; }
  .scroll { max-height: 330px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: #d0d5dd transparent; }
  .scroll::-webkit-scrollbar { width: 6px; }
  .scroll::-webkit-scrollbar-thumb { background: #d0d5dd; border-radius: 3px; }
  .scrollfade::after {
    content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 28px;
    background: linear-gradient(rgba(255,255,255,0), #fff); pointer-events: none;
    border-radius: 0 0 12px 12px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    text-align: left; color: var(--faint); font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: .5px; padding: 8px 10px;
    border-bottom: 1px solid var(--line);
    position: sticky; top: 0; background: rgba(255,255,255,.92);
    -webkit-backdrop-filter: blur(8px); backdrop-filter: blur(8px);
  }
  td { padding: 8px 10px; border-bottom: 1px solid #f2f4f7; font-variant-numeric: tabular-nums; }
  tbody tr { transition: background var(--dur-fast) var(--ease-out); }
  tbody tr:hover { background: #f8fafc; }
  tbody tr:last-child td { border-bottom: none; }
  td code.ip { color: var(--blue); font-size: 12.5px; font-weight: 600; }
  .dim { color: var(--faint); font-size: 12px; }

  tr.row-enter { animation: rowin var(--dur) var(--ease-out); }
  @keyframes rowin {
    from { opacity: 0; transform: translateY(-5px); }
    to   { opacity: 1; transform: none; }
  }

  .chip {
    display: inline-block; padding: 2.5px 10px; border-radius: 999px;
    font-size: 11.5px; font-weight: 700; letter-spacing: .1px;
    transition: background var(--dur) var(--ease-out), color var(--dur) var(--ease-out);
  }
  .chip.SAFE, .chip.ALLOWED { background: var(--green-soft); color: var(--green); }
  .chip.SUSPICIOUS, .chip.THROTTLED, .chip.THROTTLE { background: var(--orange-soft); color: var(--orange); }
  .chip.ATTACK, .chip.BLOCK, .chip.BLOCKED { background: var(--red-soft); color: var(--red); }
  .chip.WARMUP, .chip.CALIBRATING { background: #f2f4f7; color: var(--muted); }

  .confbar { height: 6px; background: #f1f3f7; border-radius: 4px; min-width: 70px; position: relative; overflow: hidden; }
  .confbar i { position: absolute; inset: 0 auto 0 0; border-radius: 4px; transition: width var(--dur) var(--ease-out); }

  .actionlog {
    font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px;
    line-height: 1.9; max-height: 210px; overflow-y: auto; color: var(--muted);
  }
  .actionlog .ts { color: var(--faint); margin-right: 10px; }
  .actionlog div { animation: rowin var(--dur) var(--ease-out); }

  .benchmark-note { font-size: 12px; color: var(--faint); margin: 8px 2px 0; }
  td.hl { color: var(--blue); font-weight: 700; }
  tr.deployed td { background: var(--blue-soft); }
  tr.deployed td:first-child { border-radius: 8px 0 0 8px; }
  tr.deployed td:last-child { border-radius: 0 8px 8px 0; }

  .footer { margin-top: 34px; color: var(--faint); font-size: 12px; text-align: center; }

  .empty { color: var(--faint); text-align: center; padding: 34px 0; }

  @media (max-width: 1120px) { .kpis { grid-template-columns: repeat(3, 1fr); } .duo { grid-template-columns: 1fr; } }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
    html { scroll-behavior: auto; }
    section.card { opacity: 1; transform: none; }
  }
</style>
</head>
<body>
<header class="topbar" id="topbar">
  <div class="topbar-inner">
    <div class="logo">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
    </div>
    <div class="titles">
      <h1>Fuzzy Edge Monitor</h1>
      <p>Explainable SYN/UDP flood detection &middot; Raspberry Pi inference</p>
    </div>
    <div class="spacer"></div>
    <span id="connPill" class="pill down"><span class="dot"></span><span id="connTxt">Disconnected</span></span>
    <span id="banner" class="statechip WAIT">WAITING FOR DETECTOR</span>
    <button id="pauseBtn" class="btn" onclick="togglePause()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M10 5H7v14h3zM17 5h-3v14h3z"/></svg>
      <span id="pauseTxt">Pause</span>
    </button>
  </div>
</header>

<main>
  <div class="grid kpis">
    <section class="card" style="--i:0">
      <div class="kpi-head"><div class="t">Traffic Rate</div>
        <div class="kpi-ico blue"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div></div>
      <div class="v blue" id="k-pps">0</div>
      <div class="s" id="k-pkts">0 packets seen</div>
    </section>
    <section class="card" style="--i:1">
      <div class="kpi-head"><div class="t">Threat Score</div>
        <div class="kpi-ico red"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div></div>
      <div class="v" id="k-score">&ndash;</div>
      <div class="s" id="k-thresh">threshold &ndash;</div>
    </section>
    <section class="card" style="--i:2">
      <div class="kpi-head"><div class="t">Model / Fuzzy</div>
        <div class="kpi-ico green"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg></div></div>
      <div class="v blue" id="k-prob">&ndash;</div>
      <div class="s" id="k-fuzzy">fuzzy &ndash;</div>
    </section>
    <section class="card" style="--i:3">
      <div class="kpi-head"><div class="t">Edge Action</div>
        <div class="kpi-ico orange"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg></div></div>
      <div class="v" id="k-action">&ndash;</div>
      <div class="s" id="k-dominant">dominant source &ndash;</div>
    </section>
    <section class="card" style="--i:4">
      <div class="kpi-head"><div class="t">Mitigations</div>
        <div class="kpi-ico red"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg></div></div>
      <div class="v" id="k-mit">0 / 0</div>
      <div class="s">blocked / throttled IPs</div>
    </section>
    <section class="card" style="--i:5">
      <div class="kpi-head"><div class="t">Pi Compute</div>
        <div class="kpi-ico green"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/></svg></div></div>
      <div class="v" id="k-cpu">&ndash;</div>
      <div class="s" id="k-infer">avg inference &ndash;</div>
    </section>
  </div>

  <h2 class="sect">Live Analysis</h2>
  <div class="grid duo">
    <section class="card" style="--i:6">
      <h3>Traffic &amp; Threat Timeline <small>last 120 s</small></h3>
      <div class="chart-wrap"><canvas id="chartTraffic"></canvas></div>
      <div class="legend">
        <span><i class="dot-s" style="background:#2563eb"></i>packets/s</span>
        <span><i class="dot-s" style="background:#dc2626"></i>attack score</span>
        <span><i class="dot-s" style="background:#98a2b3"></i>threshold <b id="legend-th"></b></span>
      </div>
    </section>
    <section class="card" style="--i:7">
      <h3>Live Decision Explanation <small>current window</small></h3>
      <div id="explain"><div class="empty">Waiting for detector windows&hellip;</div></div>
    </section>
  </div>

  <h2 class="sect">Traffic &amp; Sources</h2>
  <div class="grid duo">
    <section class="card" style="--i:8">
      <h3>Live Packet Stream <small id="feedCount"></small></h3>
      <div class="scrollwrap scrollfade"><div class="scroll">
        <table>
          <thead><tr><th>Time</th><th>Source &rarr; Destination</th><th>Proto</th><th>Len</th><th>Verdict</th><th>Confidence</th></tr></thead>
          <tbody id="pktRows"><tr><td colspan="6" class="empty">No packets yet&hellip;</td></tr></tbody>
        </table>
      </div></div>
    </section>
    <section class="card" style="--i:9">
      <h3>Source Threat Board
        <button class="btn mini hbtn" onclick="control('unblock_all','')">Release all</button>
      </h3>
      <div class="scrollwrap scrollfade"><div class="scroll">
        <table>
          <thead><tr><th>Source IP</th><th>Pkts</th><th>Max score</th><th>Status</th><th>Release in</th><th>Act</th></tr></thead>
          <tbody id="ipRows"><tr><td colspan="6" class="empty">No sources yet&hellip;</td></tr></tbody>
        </table>
      </div></div>
    </section>
  </div>

  <h2 class="sect">Response Log</h2>
  <section class="card" style="--i:10">
    <h3>Mitigation Action Log</h3>
    <div id="actionLog" class="actionlog">No mitigation actions yet.</div>
  </section>

  <h2 class="sect">Model Benchmark</h2>
  <section class="card" style="--i:11">
    <h3>Test-Set Comparison <small>honest chronological hold-out &middot; accuracy / recall / cost</small></h3>
    <div id="benchmark" class="muted">Loading&hellip;</div>
    <div class="benchmark-note">Fuzzy DT is the deployed edge model: rule activations give per-decision explanations at decision-tree cost. Latency measured end-to-end on real artifacts, including the fuzzy feature step.</div>
  </section>

  <div class="footer">Explainable SYN/UDP Flood Detection in IoT Networks &middot; Lightweight Fuzzy Decision Tree &middot; edge inference on Raspberry Pi</div>
</main>

<script>
"use strict";
const $ = id => document.getElementById(id);
const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
let paused = false, evtOffset = 0, benchmarkLoaded = false, misses = 0;
const scoreSeries = [], ppsSeries = [], MAXPTS = 240;
let packetRows = [];   // newest first {key, html cells...}
let lastStateTs = 0;

function fmt(t){ return new Date(t*1000).toLocaleTimeString('en-GB', {hour12:false}); }
function cls(v){ return v==='ATTACK'?'bad':(v==='SUSPICIOUS'||v==='THROTTLED'?'warn':(v==='SAFE'?'ok':'')); }

/* number tween — animates the displayed value only */
const tweens = new Map();
function setNum(id, val, decimals){
  const el = $(id);
  if (REDUCED){ el.textContent = val.toFixed(decimals); return; }
  const from = tweens.has(id) ? tweens.get(id) : val;
  tweens.set(id, val);
  if (Math.abs(val - from) < Math.pow(10, -decimals)/2){ el.textContent = val.toFixed(decimals); return; }
  const t0 = performance.now(), DUR = 420;
  function step(t){
    const p = Math.min((t - t0)/DUR, 1), e = 1 - Math.pow(1-p, 3);
    el.textContent = (from + (val - from)*e).toFixed(decimals);
    if (p < 1 && tweens.get(id) === val) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

async function pollState(){
  try {
    const r = await fetch('/state');
    if (!r.ok) throw new Error(r.status);
    const s = await r.json();
    misses = 0;
    setConn(true);
    renderState(s);
  } catch(e){
    if (++misses >= 3) setConn(false);
  }
}

function setConn(up){
  const pill = $('connPill');
  pill.className = 'pill ' + (up ? 'live' : 'down');
  $('connTxt').textContent = up ? 'Live' : 'Disconnected';
}

function renderState(s){
  lastStateTs = s.updated;
  const b = $('banner');
  if (s.warmup){ b.textContent = 'CALIBRATING'; b.className = 'statechip WAIT'; }
  else { b.textContent = s.threat; b.className = 'statechip ' + s.threat; }

  setNum('k-pps', s.kpi.packets_per_sec ?? 0, 0);
  $('k-pkts').textContent = s.kpi.packets_total.toLocaleString() + ' packets seen';
  const cur = s.current;
  const sc = cur.score ?? 0;
  setNum('k-score', sc, 3);
  $('k-score').className = 'v ' + cls(cur.verdict);
  $('k-thresh').textContent = 'threshold ' + (s.threshold ?? 0).toFixed(3);
  setNum('k-prob', cur.model_probability ?? 0, 3);
  $('k-fuzzy').textContent = 'fuzzy ' + (cur.fuzzy_confidence ?? 0).toFixed(3);
  $('k-action').textContent = cur.action ?? '–';
  $('k-action').className = 'v ' + cls(cur.verdict);
  $('k-dominant').textContent = 'dominant source ' + (cur.dominant_source || '–');
  $('k-mit').textContent = (s.kpi.blocked_ips ?? 0) + ' / ' + (s.kpi.throttled_ips ?? 0);

  const sys = s.system || {};
  setNum('k-cpu', sys.cpu_percent != null ? sys.cpu_percent : 0, 0);
  $('k-cpu').className = 'v ' + (sys.cpu_percent > 85 ? 'bad' : sys.cpu_percent > 60 ? 'warn' : 'ok');
  const ram = (sys.ram_used_mb != null && sys.ram_total_mb != null) ? ' · RAM ' + (100*sys.ram_used_mb/sys.ram_total_mb).toFixed(0) + '%' : '';
  const temp = sys.cpu_temp_c != null ? ' · ' + sys.cpu_temp_c.toFixed(0) + '°C' : '';
  const proc = sys.proc_cpu_percent != null ? ' · det ' + sys.proc_cpu_percent.toFixed(0) + '%' : '';
  $('k-infer').textContent = 'avg inference ' + (s.kpi.avg_infer_ms ?? 0).toFixed(1) + ' ms' + proc + ram + temp;

  $('legend-th').textContent = (s.threshold ?? 0).toFixed(2);
  ppsSeries.push({t: s.updated, v: s.kpi.packets_per_sec ?? 0});
  scoreSeries.push({t: s.updated, v: cur.score ?? 0, thr: s.threshold ?? 0, threat: s.threat});
  while (ppsSeries.length > MAXPTS){ ppsSeries.shift(); scoreSeries.shift(); }
  drawTraffic();

  renderExplain(cur);
  renderSources(s.sources || []);
  renderActions(s.recent_actions || []);
}

function renderExplain(cur){
  if (!cur || !cur.rules) return;
  const entries = Object.entries(cur.rules).sort((a,b)=>b[1]-a[1]).slice(0,6);
  let html = `<div class="verdictline">
    <span class="big ${cls(cur.verdict)}">${cur.verdict ?? '–'}</span>
    <span class="mutedline">window of ${cur.packets_in_window} pkts · model ${(cur.model_probability??0).toFixed(3)} · fuzzy ${(cur.fuzzy_confidence??0).toFixed(3)} · score ${(cur.score??0).toFixed(3)}</span></div>`;
  if (!entries.length) html += '<div class="empty">No rule data.</div>';
  for (const [name, act] of entries){
    const pct = Math.min(act*100, 100);
    html += `<div class="rule"><div class="lbl"><span>${name}</span><b>${act.toFixed(2)}</b></div>
             <div class="bar"><i style="width:${pct}%"></i></div></div>`;
  }
  html += `<div class="footnote">Rule activations are min-compositions of triangular membership grades (LOW / MEDIUM / HIGH) over window features; every rule is gated by attack direction so victim replies cannot fire.</div>`;
  $('explain').innerHTML = html;
}

function renderSources(sources){
  const tb = $('ipRows');
  if (!sources.length){ tb.innerHTML = '<tr><td colspan="6" class="empty">No sources yet…</td></tr>'; return; }
  const now = Date.now()/1000;
  tb.innerHTML = sources.map(x => {
    const rel = x.blocked_until ? Math.max(0, x.blocked_until - now) : null;
    const relTxt = rel != null ? (rel>=60 ? Math.floor(rel/60)+'m '+Math.floor(rel%60)+'s' : rel.toFixed(0)+'s') : '–';
    const btn = (x.status === 'BLOCKED' || x.status === 'THROTTLED')
      ? `<button class="btn mini" onclick="control('unblock','${x.ip}')">Release</button>`
      : `<button class="btn mini danger" onclick="control('block','${x.ip}')">Block</button>`;
    return `<tr>
      <td><code class="ip">${x.ip}</code></td>
      <td>${x.packets.toLocaleString()}</td>
      <td>${x.score_max.toFixed(3)}</td>
      <td><span class="chip ${x.status}">${x.status}</span></td>
      <td>${relTxt}</td>
      <td>${btn}</td></tr>`;
  }).join('');
}

function renderActions(actions){
  if (!actions.length) return;
  $('actionLog').innerHTML = actions.slice().reverse().map(a =>
    `<div><span class="ts">${fmt(a.ts)}</span>${a.msg}</div>`).join('');
}

async function pollEvents(){
  try {
    const r = await fetch('/events?since=' + evtOffset);
    if (!r.ok) return;
    const d = await r.json();
    if (d.reset) evtOffset = 0;
    evtOffset = d.offset;
    const fresh = d.packets || [];
    if (fresh.length){
      packetRows = [...fresh.slice().reverse(), ...packetRows].slice(0, 60);
      $('feedCount').textContent = '· last ' + packetRows.length;
      $('pktRows').innerHTML = packetRows.map((p, i) => {
        const conf = Math.min(p.confidence ?? 0, 1);
        const col = p.verdict==='ATTACK' ? '#dc2626' : p.verdict==='SUSPICIOUS' ? '#ea8a0c' : '#16a34a';
        const enter = (i < fresh.length && !REDUCED) ? ' class="row-enter"' : '';
        return `<tr${enter}>
          <td>${fmt(p.timestamp)}</td>
          <td><code class="ip">${p.src}</code> <span class="dim">→ ${p.dst}</span></td>
          <td>${p.proto}</td><td>${p.length}</td>
          <td style="font-weight:700" class="${cls(p.verdict)}">${p.verdict}</td>
          <td><div class="confbar"><i style="width:${conf*100}%;background:${col}"></i></div></td></tr>`;
      }).join('');
    }
  } catch(e){}
}

async function loadBenchmark(){
  if (benchmarkLoaded) return;
  try {
    const r = await fetch('/benchmark');
    const d = await r.json();
    const models = d.models || [];
    if (!models.length){ $('benchmark').textContent = 'Run compare_models.py to generate the benchmark.'; return; }
    const lat = d.latency_ms_per_packet || {};
    const sz = d.model_sizes || {};
    let html = '<div class="scrollwrap"><table><thead><tr><th>Model</th><th>Accuracy</th><th>Recall</th><th>Precision</th><th>F1</th><th>ROC AUC</th><th>Latency (ms/pkt)</th><th>Size</th></tr></thead><tbody>';
    for (const m of models){
      const deployed = m.deployed ? ' class="deployed"' : '';
      const name = m.deployed ? `<b>${m.model}</b> <span class="chip SAFE">deployed</span>` : `<b>${m.model}</b>`;
      html += `<tr${deployed}><td>${name}</td><td class="hl">${(m['accuracy_%']??0).toFixed(1)}%</td><td>${(m['recall_%']??0).toFixed(1)}%</td>
               <td>${m['precision_%']!=null?(m['precision_%']).toFixed(1)+'%':'–'}</td>
               <td>${(m['F1']??0).toFixed(3)}</td><td>${(m['AUC']??0).toFixed(3)}</td>
               <td>${lat[m.model]!=null?lat[m.model].toFixed(4):'–'}</td><td>${sz[m.model]??'–'}</td></tr>`;
    }
    html += '</tbody></table></div>';
    $('benchmark').innerHTML = html;
    benchmarkLoaded = true;
  } catch(e){ $('benchmark').textContent = 'Benchmark unavailable.'; }
}

/* ---------- control ---------- */
async function control(op, ip){
  try {
    await fetch('/control', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({op, ip}) });
  } catch(e){ alert('Control endpoint unreachable'); }
}

/* ---------- traffic chart ---------- */
function drawTraffic(){
  const cv = $('chartTraffic');
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w*dpr)){ cv.width = Math.round(w*dpr); cv.height = Math.round(h*dpr); }
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,w,h);
  if (ppsSeries.length < 2) return;
  const t0 = ppsSeries[0].t, t1 = ppsSeries[ppsSeries.length-1].t || 1;
  const maxPps = Math.max(10, ...ppsSeries.map(p=>p.v));
  const X = t => 30 + (t - t0) / Math.max(t1-t0, 1) * (w-38);
  const Y = (v, vmax) => h - 18 - (v / vmax) * (h-30);

  // attack shading
  for (let i=1;i<scoreSeries.length;i++){
    if (scoreSeries[i].threat === 'ATTACK'){
      ctx.fillStyle = 'rgba(220,38,38,.07)';
      ctx.fillRect(X(scoreSeries[i-1].t), 8, X(scoreSeries[i].t)-X(scoreSeries[i-1].t)+1, h-26);
    }
  }
  // gridlines
  ctx.strokeStyle = '#eef0f4'; ctx.fillStyle = '#98a2b3'; ctx.font = '10px -apple-system, sans-serif';
  for (let g=0; g<=2; g++){
    const y = Y(maxPps*g/2, maxPps);
    ctx.beginPath(); ctx.moveTo(30,y); ctx.lineTo(w-8,y); ctx.stroke();
    ctx.fillText(Math.round(maxPps*g/2), 4, y+3);
  }
  // pps area
  ctx.beginPath();
  ppsSeries.forEach((p,i)=>{ const x=X(p.t), y=Y(p.v,maxPps); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
  ctx.strokeStyle = '#2563eb'; ctx.lineWidth = 1.8; ctx.lineJoin = 'round'; ctx.stroke();
  ctx.lineTo(X(ppsSeries[ppsSeries.length-1].t), h-18); ctx.lineTo(X(ppsSeries[0].t), h-18); ctx.closePath();
  ctx.fillStyle = 'rgba(37,99,235,.08)'; ctx.fill();
  // score line (0..1)
  ctx.beginPath();
  scoreSeries.forEach((p,i)=>{ const x=X(p.t), y=Y(p.v,1); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
  ctx.strokeStyle = '#dc2626'; ctx.lineWidth = 1.5; ctx.stroke();
  // threshold
  const thr = scoreSeries[scoreSeries.length-1].thr ?? 0;
  if (thr > 0){
    ctx.setLineDash([4,4]); ctx.strokeStyle = '#98a2b3';
    ctx.beginPath(); ctx.moveTo(30, Y(thr,1)); ctx.lineTo(w-8, Y(thr,1)); ctx.stroke();
    ctx.setLineDash([]);
  }
}

function togglePause(){
  paused = !paused;
  $('pauseTxt').textContent = paused ? 'Resume' : 'Pause';
  $('pauseBtn').style.borderColor = paused ? '#f59e0b' : '';
  $('pauseBtn').style.color = paused ? '#ea8a0c' : '';
}

addEventListener('scroll', () => {
  $('topbar').classList.toggle('scrolled', scrollY > 4);
}, {passive: true});
addEventListener('resize', drawTraffic);

loadBenchmark();
setInterval(()=>{ if(!paused) pollState(); }, 1000);
setInterval(()=>{ if(!paused) pollEvents(); }, 1000);
pollState(); pollEvents();
</script>
</body>
</html>"""


def make_handler(state_path: Path, events_path: Path, benchmark_path: Path, control_path: Path):
    class Handler(BaseHTTPRequestHandler):
        # ---- helpers -----------------------------------------------------
        def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(json.dumps(obj).encode(), "application/json", code)

        # ---- GET ----------------------------------------------------------
        def do_GET(self) -> None:
            if self.path == "/state":
                try:
                    self._send(state_path.read_bytes(), "application/json")
                except FileNotFoundError:
                    self._json({"error": "no detector state yet — start live_detector.py"})
                return

            if self.path.startswith("/events"):
                since = 0
                if "since=" in self.path:
                    try:
                        since = int(self.path.split("since=")[1].split("&")[0])
                    except ValueError:
                        since = 0
                out = {"offset": since, "packets": [], "reset": False}
                try:
                    size = events_path.stat().st_size
                    if since > size:  # log rotated
                        since, out["reset"] = 0, True
                    with events_path.open("r", encoding="utf-8") as f:
                        if since:
                            f.seek(since)
                        new_text = f.read()
                    out["offset"] = since + len(new_text.encode("utf-8"))
                    packets = []
                    for line in new_text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:  # partial last line
                            out["offset"] = since
                            continue
                        if ev.get("type") == "packet":
                            packets.append(ev)
                except FileNotFoundError:
                    pass
                out["packets"] = packets[-80:]  # keep the response light
                self._json(out)
                return

            if self.path == "/benchmark":
                try:
                    self._send(benchmark_path.read_bytes(), "application/json")
                except FileNotFoundError:
                    self._json({})
                return

            self._send(PAGE.encode(), "text/html")

        # ---- POST (control buttons) ----------------------------------------
        def do_POST(self) -> None:
            if self.path != "/control":
                self._json({"error": "unknown endpoint"}, 404)
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
                op, ip = str(req.get("op", "")), str(req.get("ip", ""))
                if op not in ("block", "unblock", "unblock_all") or (op != "unblock_all" and not ip):
                    self._json({"error": "bad command"}, 400)
                    return
                data = {"next_id": 1, "commands": []}
                try:
                    data = json.loads(control_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
                cmd = {"id": int(data.get("next_id", 1)), "op": op, "ip": ip, "ts": time.time()}
                data["next_id"] = cmd["id"] + 1
                cmds = list(data.get("commands", []))[-40:] + [cmd]
                data["commands"] = cmds
                control_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = control_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                os.replace(tmp, control_path)
                self._json({"ok": True, "command": cmd})
            except Exception as err:  # noqa: BLE001
                self._json({"error": str(err)}, 500)

        def log_message(self, *_args):
            return

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT Edge Flood Monitor Dashboard")
    parser.add_argument("--state", default="reports/detector_state.json")
    parser.add_argument("--events", default="reports/monitor_events.jsonl")
    parser.add_argument("--benchmark", default="reports/model_comparison_report.json")
    parser.add_argument("--control", default="reports/control_commands.json")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    # Allow running from repo root or from implementation/
    def resolve(p: str) -> Path:
        path = Path(p)
        if path.exists():
            return path
        alt = Path(__file__).parent / p
        return alt if alt.exists() else path

    server = ThreadingHTTPServer(
        (args.host, args.port),
        make_handler(resolve(args.state), resolve(args.events), resolve(args.benchmark), Path(args.control)),
    )
    print(f"IoT Edge Flood Monitor dashboard: http://{args.host}:{args.port}")
    print(f"  state:    {args.state}")
    print(f"  events:   {args.events}")
    print(f"  control:  {args.control}")
    server.serve_forever()


if __name__ == "__main__":
    main()

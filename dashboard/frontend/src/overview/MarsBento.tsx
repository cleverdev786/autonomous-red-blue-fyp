import { useEffect, useRef } from "react";
import type { PointerEvent } from "react";

const steps = ["Test selected", "Scope authorized", "Baseline HTTP", "Evidence captured", "Blue handoff"];
const controls = ["SQLi", "XSS", "Traversal", "Benign", "Registry", "Policy", "Sandbox", "Audit"];
const points = [61,56,53,49,46,43,41,39,36,34,30,27].map((v,i) =>
  `${(240*i/11).toFixed(1)},${(8+(61-v)*48/34).toFixed(1)}`).join(" ");

export function MarsBento() {
  const grid = useRef<HTMLUListElement>(null);
  const frame = useRef<number | null>(null);
  const pointer = useRef<{x:number;y:number}|null>(null);
  useEffect(() => () => { if(frame.current !== null) cancelAnimationFrame(frame.current); }, []);
  function onMove(event: PointerEvent<HTMLUListElement>) {
    if(event.pointerType === "touch") return;
    pointer.current = {x:event.clientX,y:event.clientY};
    if(frame.current !== null) return;
    frame.current = requestAnimationFrame(() => {
      frame.current = null;
      if (!pointer.current || !grid.current) return;
      grid.current.querySelectorAll<HTMLElement>(".mars-bento-tile").forEach(tile => {
        const rect = tile.getBoundingClientRect();
        tile.style.setProperty("--mx", `${pointer.current!.x - rect.left}px`);
        tile.style.setProperty("--my", `${pointer.current!.y - rect.top}px`);
      });
    });
  }
  function onLeave() {
    grid.current?.classList.remove("mars-bento--lit");
    pointer.current = null;
    if(frame.current !== null) cancelAnimationFrame(frame.current);
    frame.current = null;
  }

  return <section className="mars-bento-section" aria-labelledby="mars-bento-heading">
    <header className="mars-bento-header">
      <span className="mars-bento-eyebrow">Inside MARS</span>
      <h2 id="mars-bento-heading">From a registered test to a verified fix.</h2>
      <p>Local Red and Blue workflows built around evidence and repeatable checks. Visuals illustrate the process, not live test results.</p>
    </header>
    <ul className="mars-bento" role="list" ref={grid} onPointerMove={onMove}
      onPointerEnter={event => { if(event.pointerType !== "touch") grid.current?.classList.add("mars-bento--lit"); }}
      onPointerLeave={onLeave}>
      <li className="mars-bento-tile mars-bento-a">
        <h3>Registered Red tests</h3><p>Only approved SQLi, XSS, and traversal probes execute in the local lab.</p>
        <div className="mars-bento-visual" aria-hidden="true"><div className="mars-bento-log">
          {steps.map((step,i) => <div key={step} className="mars-bento-log-line"
            style={{animationDelay:`${i*.5}s`}}>
            <span>{i===4?"●":"✓"}</span><span>{step}</span><time>{String(i+1).padStart(2,"0")}</time>
          </div>)}
          <div className="mars-bento-progress"><span/></div>
        </div></div>
      </li>
      <li className="mars-bento-tile mars-bento-b">
        <h3>Offline fallback</h3><p>Registered local tools work without any model or cloud API.</p>
        <div className="mars-bento-visual" aria-hidden="true"><div className="mars-bento-region-grid">
          {controls.map((name,i) => <span key={name}><i style={{animationDelay:`${i*.3}s`}}/>{name}</span>)}
        </div></div>
      </li>
      <li className="mars-bento-tile mars-bento-c">
        <h3>Trusted patch templates</h3><p>Code identity and policy are verified before preparation.</p>
        <div className="mars-bento-visual" aria-hidden="true"><div className="mars-bento-versions">
          <div className="mars-bento-current"><span>source SHA</span><small>pinned</small></div>
          <div><span>AST anchor</span><small>checked</small></div>
          <div><span>template</span><small>review</small></div>
        </div></div>
      </li>
      <li className="mars-bento-tile mars-bento-d">
        <h3>Verification without a model</h3><p>The registered attack is replayed against a trusted patch offline.</p>
        <div className="mars-bento-visual" aria-hidden="true"><div className="mars-bento-trace-panel">
          <div className="mars-bento-trace-count"><strong>2</strong><span>test phases</span></div>
          <div className="mars-bento-trace-chart">
            <svg viewBox="0 0 240 64" preserveAspectRatio="none" role="presentation">
              <defs><linearGradient id="mars-bento-area" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#FF6A3D" stopOpacity=".22"/>
                <stop offset="100%" stopColor="#FF6A3D" stopOpacity="0"/>
              </linearGradient></defs>
              <polygon className="mars-bento-trace-area" points={`0,64 ${points} 240,64`} fill="url(#mars-bento-area)"/>
              <polyline className="mars-bento-trace" points={points} pathLength="1" stroke="#FF6A3D"
                strokeWidth="1.5" vectorEffect="non-scaling-stroke" fill="none"/>
            </svg>
            <span className="mars-bento-end-dot"/>
            <div className="mars-bento-trace-labels"><span>baseline</span><span>retest</span></div>
          </div>
        </div></div>
      </li>
      <li className="mars-bento-tile mars-bento-e">
        <h3>Disposable test environments</h3><p>Baseline and patched applications stay separate from live source.</p>
        <div className="mars-bento-visual" aria-hidden="true">
          <svg className="mars-bento-branches" viewBox="0 0 340 88" preserveAspectRatio="xMinYMid meet">
            <g fill="none" strokeWidth="1.5" strokeLinecap="round">
              <path d="M60 18H327" stroke="#5E5D58"/>
              <path d="M156 18C177 18 178 48 198 48H220" stroke="#FF6A3D"/>
              <path d="M60 18C82 18 83 74 105 74H124" stroke="#5E5D58"/>
            </g>
            {[60,156,260].map(x=><circle key={x} cx={x} cy="18" r="4" fill="#77756F"/>)}
            <circle cx="220" cy="48" r="4" fill="#FF6A3D"/>
            <circle className="mars-bento-branch-pulse" cx="220" cy="48" r="4" fill="#FF6A3D"/>
            <circle cx="124" cy="74" r="4" fill="#8B8A84"/>
            <g fontFamily="ui-monospace, Consolas, monospace" fontSize="11">
              <text x="0" y="22" fill="#aaa9a4">source</text>
              <text x="230" y="52" fill="#f2f1ec">patched</text>
              <text x="134" y="78" fill="#aaa9a4">baseline</text>
            </g>
          </svg>
        </div>
      </li>
      <li className="mars-bento-tile mars-bento-f">
        <h3>Evidence receipts</h3><p>Source hashes, HTTP observations, and regression outcomes are reviewable.</p>
        <div className="mars-bento-visual" aria-hidden="true"><div className="mars-bento-chips">
          <span><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor"
            strokeWidth="1.75" strokeLinecap="round" role="presentation">
            <rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>
          </svg>SHA-256</span>
          <span>HTTP replay</span><span>Regression</span>
        </div></div>
      </li>
    </ul>
  </section>;
}

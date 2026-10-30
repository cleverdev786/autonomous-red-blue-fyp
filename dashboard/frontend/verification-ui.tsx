// Development-only fixture page. Vite's production build includes index.html only.
import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import axe from "axe-core";
import { AssessmentWorkspaceView } from "./src/red/AssessmentWorkspace";
import { NewAssessmentView } from "./src/red/NewAssessmentView";
import { RedDashboardView } from "./src/red/RedDashboardView";
import { RedOverviewView } from "./src/overview/RedOverview";
import { LoginScreen } from "./src/LoginScreen";
import { NotificationCenter, notify } from "./src/ui";
import type { RedWorkspaceBundle, RedTarget } from "./src/red/api";
import "./src/tokens.css";
import "./src/styles.css";
import "./src/product.css";
import "./src/shell.css";
import "./src/workspace.css";

const target: RedTarget = { target_id:"fixture-target-with-a-long-registered-name", compatibility:"supported",
  supported_classes:["sql_injection","xss","path_traversal"],limitations:["unauthenticated_only"],
  standard_budget:{profile:"standard",max_http_requests:24,max_crawl_requests:12,max_tests:3,max_runtime_seconds:180,
    max_parallel_operations:1,max_depth:2,max_retries:0,max_cpu_cores:.5,max_memory_mb:512} };
const assessment = {assessment_id:"fixture-assessment",target_id:target.target_id,mode:"manual" as const,
  profile:"standard" as const,status:"queued" as const,workflow_complete:false,
  coverage:{eligible:3,executed:1,completed:1,blocked:1,skipped:1,observed_candidate_gaps:1,unresolved_observations:1,coverage_complete:false},
  current_plan_version:"plan-1",current_surface_revision:"surface-1",
  stage_statuses:{reconnaissance:"succeeded",planning:"stale",execution:"blocked",verification:"not_started"} as const};
const bundle:RedWorkspaceBundle={workspace:{assessment,stages:Object.entries(assessment.stage_statuses).map(([stage,status])=>({stage:stage as keyof typeof assessment.stage_statuses,status,plan_version:"plan-1"})),
  plans:[{plan_version:"plan-1",surface_revision:"surface-1",status:"stale"}],candidate_count:3,planned_operation_count:1,
  finding_counts:{suspected:1,confirmed:0,not_confirmed:0,inconclusive:0},coverage_gap_count:1},
  events:[{event_id:"event-1",action:"stage-transition",status:"blocked",stage:"execution",occurred_at:"2026-10-30T10:00:00Z"}],
  findings:[{finding_id:"fixture-finding",assessment_id:assessment.assessment_id,target_id:target.target_id,
    status:"suspected",severity:"medium",category:"xss",route:"/very/long/registered/path/with/parameters?query=fixture",provenance:null,reproduction_scope:null,has_evidence:false}],
  findingTotal:1,coverage:{assessment_id:assessment.assessment_id,target_id:target.target_id,coverage:assessment.coverage,
    gaps:[{gap_id:"gap-1",status:"open",reason:"authentication_required",candidate_id:null,test_id:null,recommendation:"Authenticated routes were not assessed."}],
    warnings:["unauthenticated_only_coverage"]}};
const noop=()=>{};
// Refuse all writes and all unrecognized requests from fixture interactions.
window.fetch=async(input,options)=>{
  if(options?.method && options.method!=="GET") throw new Error("Fixture page blocks writes");
  if(String(input).includes("/findings/fixture-finding")) return new Response(JSON.stringify({
    finding:bundle.findings[0],operation_id:"op-1",plan_version:"plan-1",test_id:"test-1",oracle_id:"oracle-1",
    evidence_receipt_ids:["receipt-1"],evidence:[{evidence_id:"evidence-1",receipt_id:"receipt-1",operation_id:"op-1",sha256:"a".repeat(64),content_type:"application/json"}]
  }),{headers:{"Content-Type":"application/json"}});
  throw new Error("Fixture page blocks network requests");
};
function QA(){
  const [surface,setSurface]=useState(()=>new URLSearchParams(location.search).get("surface")??"workspace");
  const [theme,setTheme]=useState(()=>new URLSearchParams(location.search).get("theme")==="dark"?"dark":"light");
  const [phase,setPhase]=useState("setup");
  const [mode,setMode]=useState<"manual"|"autonomous">("manual");
  const [selected,setSelected]=useState("");
  const [result,setResult]=useState("Not run");
  useEffect(()=>{ document.documentElement.dataset.theme=theme; },[theme]);
  useEffect(()=>{
    const audited = new WeakSet<Element>();
    const observer = new MutationObserver(async()=>{
      const overlay=document.querySelector('[role="dialog"],[role="listbox"]');
      if (!overlay || (overlay.getAttribute("role")==="dialog" && !overlay.querySelector(".evidence-content")) || audited.has(overlay)) return;
      audited.add(overlay);
      await Promise.allSettled(overlay.getAnimations({subtree:true}).filter(a=>a.effect?.getComputedTiming().iterations!==Infinity).map(a=>a.finished));
      const audit=await axe.run(overlay,{runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21a","wcag21aa"]}});
      setResult(JSON.stringify({surface:overlay.getAttribute("role")==="dialog"?"evidence-dialog":"dropdown",theme:document.documentElement.dataset.theme??"light",viewport:innerWidth,
        violations:audit.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)})),
        incomplete:audit.incomplete.map(v=>({id:v.id,nodes:v.nodes.length,details:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})),passes:audit.passes.length},null,2));
    });
    observer.observe(document.body,{childList:true,subtree:true});
    return ()=>observer.disconnect();
  },[]);
  const summary={target_id:null,assessment_count:1,confirmed_findings:0,suspected_findings:1,tested:1,eligible:3,active_assessments:1,queued_assessments:1,active_stages:0,coverage_gaps:1};
  return <main className="qa-main">
    <h1>MARS UI verification · fixtures only</h1>
    <p>No live assessments or backend writes. Evidence data is synthetic.</p>
    <div className="qa-controls">
      <label>Surface <select value={surface} onChange={e=>setSurface(e.target.value)}>
        {["workspace","autonomous","setup","empty","error","loading","dashboard","overview","login"].map(item=><option key={item}>{item}</option>)}
      </select></label>
      <label>Theme <select value={theme} onChange={e=>{setTheme(e.target.value);document.documentElement.dataset.theme=e.target.value;}}>
        <option>light</option><option>dark</option>
      </select></label>
      <button type="button" onClick={async()=>{
        setResult("Running accessibility audit…");
        await Promise.allSettled(document.getAnimations().filter(animation =>
          animation.effect?.getComputedTiming().iterations !== Infinity).map(animation => animation.finished));
        const audit=await axe.run(document.getElementById("fixture")!,{runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21a","wcag21aa"]}});
        setResult(JSON.stringify({surface,theme,viewport:innerWidth,violations:audit.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})),incomplete:audit.incomplete.map(v=>({id:v.id,nodes:v.nodes.length,details:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})),passes:audit.passes.length},null,2));
      }}>Run accessibility audit</button>
      <button type="button" onClick={()=>notify("Fixture notification. No action performed.")}>Preview notification</button>
    </div>
    <section id="fixture" aria-label="Verification surface">
      {surface==="login"?<LoginScreen checking={false} onSignedIn={noop}/>:
        surface==="setup"?<NewAssessmentView targets={[target]} targetId={selected} mode={mode} phase={phase as "setup"|"review"} busy={false} error={null} assessmentId={null}
          onTargetChange={setSelected} onModeChange={setMode} onReview={()=>setPhase("review")} onCreate={noop} onAuthorize={noop} onStart={noop} onCancel={noop} onEdit={()=>setPhase("setup")} onReset={noop}/>:
        surface==="overview"?<RedOverviewView state={{kind:"error",denied:true}} onRetry={noop}/>:
        ["empty","error","loading","dashboard"].includes(surface)?<RedDashboardView targets={[target]} targetId="" status="" state={surface==="loading"?{kind:"loading"}:surface==="error"?{kind:"error",message:"Fixture service unavailable."}:{kind:"ready",summary,assessments:surface==="empty"?[]:[assessment],total:surface==="empty"?0:1,offset:0,limit:25}}
          onTargetChange={noop} onStatusChange={noop} onRefresh={noop} onPageChange={noop} onInspect={noop}/>:
        <AssessmentWorkspaceView data={surface==="autonomous"?{...bundle,workspace:{...bundle.workspace,assessment:{...assessment,mode:"autonomous",status:"running"}}}:bundle}
          token="" busy={null} commandError={null} onClose={noop} onRefresh={noop} onRunStage={noop} onCancel={noop}/>}
    </section>
    <pre id="audit-result" aria-label="Audit result">{result}</pre>
    <NotificationCenter/>
  </main>;
}
createRoot(document.getElementById("root")!).render(<QA/>);

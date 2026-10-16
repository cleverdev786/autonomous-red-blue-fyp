"use strict";
const assert=require("node:assert/strict");
const esbuild=require("esbuild");
const path=require("node:path");
const {createRequire}=require("node:module");
const built=esbuild.buildSync({entryPoints:["src/api.ts"],bundle:true,platform:"node",
  format:"cjs",packages:"external",write:false,define:{"import.meta.env.VITE_API_BASE_URL":"undefined"}});
const compiled={exports:{}};
new Function("module","exports","require",built.outputFiles[0].text)(
  compiled,compiled.exports,createRequire(path.resolve("package.json")));
const {requestJson,getJson,getConsoleJson,ApiRequestError,startLocalModel,stopLocalModel,getMarsRedPreflight,getMarsJobExecution,getMarsJobProposal}=compiled.exports;
const response=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json"}});
const check=async(kind,promise)=>{
  await assert.rejects(promise,error=>error instanceof ApiRequestError && error.kind===kind);
};
(async()=>{
  assert.equal(typeof requestJson,"function");
  assert.equal(typeof ApiRequestError,"function");
  global.fetch=async()=>response({status:"ok",database_read_only:true,database_available:false});
  assert.equal((await getJson("/health")).database_available,false);
  global.fetch=async()=>response({status:"ok",database_read_only:"yes"});
  await check("schema",getJson("/health"));
  global.fetch=async()=>response({detail:"unavailable"},503);
  await check("http",getJson("/health"));
  global.fetch=async()=>{throw new TypeError("offline")};
  await check("network",getJson("/health"));
  global.fetch=async()=>({ok:true,json:async()=>{throw new SyntaxError("malformed")}});
  await check("schema",getJson("/health"));
  global.fetch=async(_url,options)=>new Promise((_,reject)=>{
    options.signal.addEventListener("abort",()=>reject(new DOMException("Aborted","AbortError")));
  });
  await check("timeout",requestJson("/api/health",undefined,15));
  const controller=new AbortController();
  const aborted=requestJson("/api/health",{signal:controller.signal},1000);
  controller.abort();
  await check("aborted",aborted);
  global.fetch=async()=>response([{run_id:"fixture",status:"blocked"}]);
  await check("schema",getJson("/runs"));
  global.fetch=async()=>response({prepared:true,applied:false,verified:false,final_research:false,
    scenario:"sql",title:"SQL injection",registered_test_id:"sqli-login-bypass-001",prepared_diff_sha256:"0".repeat(64),
    diff_preview:"",notice:"Not applied"});
  const preview=await requestJson("/api/console/preview",{},500);
  assert.equal(preview.applied,false);
  global.fetch=async()=>response({target:"local",execution_mode:"controlled",experience_mode:"DISABLED",model:{state:"unloaded",final_research_ready:"yes"}});
  await check("schema",getConsoleJson("/status"));
  global.fetch=async()=>response({prepared:true,applied:false,verified:"false",final_research:false,
    scenario:"sql",title:"SQL injection",registered_test_id:"sqli-login-bypass-001",
    prepared_diff_sha256:"0".repeat(64),diff_preview:"",notice:"Unverified"});
  await check("schema",requestJson("/api/console/preview",{},500));
  const writes=[];
  global.fetch=async(url,opts)=>{writes.push({url,method:opts.method,body:opts.body});
    return response({state:"starting",final_research_ready:false});};
  await startLocalModel("approved.gguf","local-security-model");
  await stopLocalModel();
  assert.deepEqual(writes.map(x=>[x.url,x.method]),[
    ["/api/console/models/load","POST"],["/api/console/models/unload","POST"]]);
  assert.deepEqual(JSON.parse(writes[0].body),{filename:"approved.gguf",model_name:"local-security-model"});
  const safePreflight = {schema_version:"mars-red-preflight-v1",job_id:"fixture-job",
    registered_test_id:"sqli-login-bypass-001",scope_sha256:"a".repeat(64),
    scope_current:true,checks:{job_scope_reviewed:true,registered_scope_current:true,
      independent_admission_verified:false,isolated_runtime_verified:false,
      runner_enabled:false},can_dispatch:false,note:"Not admitted"};
  global.fetch=async()=>response(safePreflight);
  assert.equal((await getMarsRedPreflight("fixture-job")).can_dispatch,false);
  global.fetch=async()=>response({...safePreflight,can_dispatch:true});
  await check("schema",getMarsRedPreflight("fixture-job"));
  global.fetch=async()=>response({...safePreflight,checks:{...safePreflight.checks,runner_enabled:true}});
  await check("schema",getMarsRedPreflight("fixture-job"));
  const unknownExecution = {job_id:"fixture-job",status:"outcome_unknown",
    scope:"development_only_not_final_research"};
  global.fetch=async()=>response(unknownExecution);
  assert.equal((await getMarsJobExecution("fixture-job")).status,"outcome_unknown");
  global.fetch=async()=>response({...unknownExecution,scope:"final_research"});
  await check("schema",getMarsJobExecution("fixture-job"));
  global.fetch=async()=>response({...unknownExecution,status:"receipt_recorded",
    outcome:"baseline_exploit_confirmed"});
  await check("schema",getMarsJobExecution("fixture-job"));
  const emptyProposal = {job_id:"fixture-job",status:"not_prepared",patch_applied:false,
    model_decision_used:false,security_replayed:false,final_research_qualified:false};
  global.fetch=async()=>response(emptyProposal);
  assert.equal((await getMarsJobProposal("fixture-job")).status,"not_prepared");
  global.fetch=async()=>response({...emptyProposal,patch_applied:true});
  await check("schema",getMarsJobProposal("fixture-job"));
  global.fetch=async()=>response({...emptyProposal,status:"prepared",
    origin:"trusted_deterministic_builder",red_run_id:"r1",
    red_receipt_sha256:"b".repeat(64),registered_test_id:"sqli-login-bypass-001",
    source_file:"dummy_apps/vulnerable_store/app/scenario_routes.py",
    diff_sha256:"a".repeat(64),diff_preview:"--- source",note:"Development only"});
  assert.equal((await getMarsJobProposal("fixture-job")).status,"prepared");
  console.log("M14 API tests: health, HTTP, network, abort, preview refusal, receipt and proposal validation = PASS");
})().catch(error=>{console.error(error);process.exitCode=1});

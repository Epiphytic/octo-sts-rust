// Run after worker-build --release; NODE_PATH must resolve the pinned Miniflare
// installation accompanying Wrangler. All outbound GitHub traffic is intercepted.
const { Miniflare } = require('miniflare');
const { execFileSync } = require('node:child_process');
const { generateKeyPairSync } = require('node:crypto');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
const fixture = JSON.parse(execFileSync('cargo', ['run','--quiet','--locked','-p','octo-sts-core','--example','nostr-fixture'], {cwd:root}));
const privateKey = generateKeyPairSync('rsa', {modulusLength:2048}).privateKey.export({type:'pkcs8',format:'pem'});
const persist = mkdtempSync(path.join(tmpdir(), 'nostr-replay-'));
let issued = 0;
const options = {
  modules:true, scriptPath:path.join(root,'cloudflare/build/index.js'),
  modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],
  compatibilityDate:'2024-01-01', compatibilityFlags:['nodejs_compat'],
  durableObjects:{NOSTR_REPLAY:{className:'NostrReplay',useSQLite:true}},
  durableObjectsPersist:persist,
  bindings:{NOSTR_EXCHANGE_ENABLED:'true',NOSTR_EXCHANGE_URL:fixture.url,NOSTR_RATE_PER_MINUTE:'10',GITHUB_APP_ID:'1',GITHUB_APP_PRIVATE_KEY:privateKey},
  outboundService: async request => {
    const url = new URL(request.url);
    assert.equal(url.hostname,'api.github.com');
    if(url.pathname.endsWith('/installation')) return Response.json({id:42});
    if(url.pathname.includes('/contents/')) return new Response(fixture.policy);
    assert.equal(url.pathname,'/app/installations/42/access_tokens');
    const body = await request.json();
    if(body.repositories[0] === 'one') {
      assert.deepEqual(body.repositories,['one']);
      assert.deepEqual(body.permissions,{contents:'read'});
      issued++;
    } else assert.deepEqual(body.repositories,['.github']);
    return Response.json({token:'local-fixture-only',expires_at:new Date(Date.now()+3600000).toISOString()},{status:201});
  }
};
(async()=>{
  let mf = new Miniflare({durableObjectsPersist:persist,workers:[options]});
  try {
    const request = () => mf.dispatchFetch(fixture.url,{method:'POST',headers:{'content-type':'application/json',authorization:fixture.authorization},body:fixture.body});
    const start = performance.now();
    const results = await Promise.all(Array.from({length:8},request));
    assert.equal(results.filter(r=>r.status===200).length,1, JSON.stringify(await Promise.all(results.map(async r=>({status:r.status,body:await r.clone().text()})))));
    assert.equal(results.filter(r=>r.status===401).length,7);
    assert.equal(issued,1);
    for(const response of results) assert.equal(response.headers.get('cache-control'),'no-store');
    console.log(`WASM concurrent signed exchange: one issuance, seven replays (${Math.round(performance.now()-start)} ms wall time)`);
    await mf.dispose();
    mf = new Miniflare({durableObjectsPersist:persist,workers:[options]});
    assert.equal((await request()).status,401);
    assert.equal(issued,1);
    console.log('Durable replay survives runtime restart');
    const bad = await mf.dispatchFetch(fixture.url,{method:'POST',headers:{'content-type':'application/json',authorization:fixture.authorization},body:fixture.body+' '});
    assert.equal(bad.status,401);
    await mf.setOptions({durableObjectsPersist:persist,workers:[{...options,bindings:{...options.bindings,NOSTR_EXCHANGE_ENABLED:'false'}}]});
    assert.equal((await request()).status,404);
    console.log('Payload tampering rejected; disabled route returns 404');
  } finally { await mf.dispose(); rmSync(persist,{recursive:true,force:true}); }
})().catch(error=>{console.error(error);process.exitCode=1;});

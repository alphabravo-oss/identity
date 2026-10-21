// Live browser proof. Requires installed playwright-core and an isolated deployed fixture.
import fs from 'node:fs';
import crypto from 'node:crypto';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const proof = process.env.PROOF_DIR;
if (!proof) throw new Error('PROOF_DIR must point to isolated fixture evidence');
const issuer = process.env.E2E_ISSUER || 'https://identity.identity.test';
const apps = JSON.parse(process.env.E2E_APPS || '{"demo-product":"https://demo.identity.test","astronomer":"https://astronomer.identity.test","constellation":"https://constellation.identity.test"}');
const executablePath = process.env.CHROMIUM || '/root/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell';
const hosts = [new URL(issuer).hostname,...Object.values(apps).map(x=>new URL(x).hostname),'kc.identity.test'];
const browser = await chromium.launch({executablePath,args:['--no-sandbox',`--host-resolver-rules=${hosts.map(h=>`MAP ${h}:443 127.0.0.1:18443`).join(', ')}`]});
const checks=[];
const check=(name,ok,details={})=>{checks.push({name,ok,...details});if(!ok)throw new Error(name+': '+JSON.stringify(details));console.log(name+': pass '+JSON.stringify(details));};
fs.mkdirSync(proof+'/shots',{recursive:true});
function totp(){const s=fs.readFileSync(process.env.E2E_TOTP_FILE||proof+'/secrets/totp','utf8').trim();let bits='';for(const c of s.replace(/=+$/,''))bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(x=>parseInt(x,2)));const n=Buffer.alloc(8);n.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',key).update(n).digest();return String((h.readUInt32BE(h[19]&15)&0x7fffffff)%1000000).padStart(6,'0');}
async function context(colorScheme='light'){const ctx=await browser.newContext({ignoreHTTPSErrors:true,colorScheme,viewport:{width:1280,height:900}});return {ctx,page:await ctx.newPage()};}
async function local(page,app='demo-product'){
 await page.goto(apps[app]+'/login');await page.waitForSelector('#u');await page.fill('#u',process.env.E2E_USER||'bob');await page.fill('#p',process.env.E2E_PASSWORD||'Identity-Proof-Pass1!');await page.click('form[action="/signin/password"] button');await page.waitForSelector('#c');await page.fill('#c',totp());await page.click('form[action="/signin/totp"] button');await page.waitForURL(apps[app]+'/');return page.textContent('body');
}
const mode=process.argv[2]||'local';
try {
 if(mode==='shots'){
  for(const theme of ['light','dark'])for(const [slug,app] of Object.entries(apps)){
   const {ctx,page}=await context(theme);await page.goto(app+'/login');await page.waitForSelector('#u');await page.screenshot({path:`${proof}/shots/${slug}-${theme}.png`});check(`branding ${slug} ${theme}`,!(await page.content()).toLowerCase().includes('zitadel'));await ctx.close();
  }
 }
 if(mode==='local'){
  const {ctx,page}=await context();const first=await local(page);check('password + TOTP to real demo',first.includes('viewer'),{body:first.trim()});
  let start=performance.now();await page.goto(apps.astronomer+'/login');await page.waitForURL(apps.astronomer+'/');const second=await page.textContent('body');check('second product uses shared session',second.includes('operator'),{ms:performance.now()-start,body:second.trim()});
  start=performance.now();await page.goto(apps.constellation+'/login');await page.waitForURL(apps.constellation+'/');check('third product has its own role',(await page.textContent('body')).includes('analyst'),{ms:performance.now()-start});
  const cookies=await ctx.cookies();fs.writeFileSync(proof+'/secrets/browser-state.json',JSON.stringify(await ctx.storageState()));let inspected='';for(const c of cookies){inspected+=c.name;if(c.name==='ab_token'){inspected+=Buffer.from(c.value.split('.')[1],'base64url').toString();}}
  check('cookies and decoded tokens have no engine name',!/zitadel/i.test(inspected));await ctx.close();
 }
 if(mode==='federated'){
  const kind=process.argv[3]||'oidc';const {ctx,page}=await context();await page.goto(apps['demo-product']+'/login');
  if(kind==='ldap'){await page.click('#ldap-toggle');await page.fill('#lu','dave');await page.fill('#lp','Ldap-Pass1!');await page.click('#ldap-submit');}
  else {await page.click('#sso-'+kind);await page.waitForSelector('#username');await page.fill('#username',process.env.E2E_UPSTREAM_USER||'kim');await page.fill('#password','Kc-Pass1!');await page.click('#kc-login');}
  await page.waitForURL(apps['demo-product']+'/',{timeout:20000});const body=await page.textContent('body');check(kind+' group mapping',process.env.E2E_NO_ROLE==='true'?!body.includes('admin'):body.includes('admin'),{body:body.trim()});await ctx.close();
 }
 if(mode==='passkey'){
  const {ctx,page}=await context();await local(page);
  const cdp=await ctx.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await page.goto(issuer+'/signin/security');await page.click('form[action="/signin/passkey/register"] button');await page.click('#passkey-button');await page.getByRole('heading',{name:'Your passkey is ready'}).waitFor();check('passkey registration',true);
  await page.goto(issuer+'/signin/logout');await ctx.clearCookies({name:'ab_token'});await page.goto(apps['demo-product']+'/login');await page.fill('#pk-user','bob');await page.click('form[action="/signin/passkey/start"] button');await page.click('#passkey-button');await page.waitForURL(apps['demo-product']+'/');check('passkey sign-in',(await page.textContent('body')).includes('viewer'));await ctx.close();
 }
 if(mode==='crawl'){
  const {ctx,page}=await context();const paths=['/signin/login','/signin/reset','/signin/invite','/signin/logout','/signin/does-not-exist','/signin/static/','/ui/console','/ui/v2/login','/management/v1/users','/v2/users','/zitadel.user.v2.UserService/ListUsers','/.well-known/openid-configuration','/oauth/v2/authorize?client_id=invalid','/oidc/v1/end_session','/idps/does-not-exist'];
  let hits=[];for(const path of paths){const response=await page.goto(issuer+path);const raw=(await page.content())+JSON.stringify(await response.allHeaders());if(/zitadel/i.test(raw))hits.push({path});}check('public paths and errors contain no engine name',hits.length===0,{paths:paths.length,hits});await ctx.close();
 }
 if(mode==='bench'){
  const n=Number(process.argv[3]||10),first=[],second=[];for(let i=0;i<n;i++){const {ctx,page}=await context();let start=performance.now();await local(page);first.push(performance.now()-start);start=performance.now();await page.goto(apps.astronomer+'/login');await page.waitForURL(apps.astronomer+'/');second.push(performance.now()-start);await ctx.close();}
  const p95=a=>a.sort((x,y)=>x-y)[Math.ceil(a.length*.95)-1];check('browser latency measurements',true,{n,loginP95:p95(first),secondProductP95:p95(second)});
 }
} finally {fs.writeFileSync(`${proof}/${mode}-checks.json`,JSON.stringify(checks,null,2));await browser.close();}

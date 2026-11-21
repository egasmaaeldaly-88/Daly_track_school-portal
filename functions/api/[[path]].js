const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function sign(env, m) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET || env.TEACHER_PASSWORD), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(m)));
}
function eq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function authed(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/(?:^|; )tk=(\d+)\.([0-9a-f]+)/);
  return !!m && +m[1] > Date.now() && eq(m[2], await sign(env, m[1]));
}
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...h } });
const F = {
  homework: ['date', 'grade', 'section', 'subject', 'text', 'link', 'author'],
  plan: ['date', 'grade', 'section', 'subject', 'text', 'author'],
  exams: ['date', 'grade', 'subject', 'title', 'coverage', 'link', 'author'],
  library: ['subject', 'title', 'type', 'link', 'author'],
  announcement: ['date', 'title', 'text', 'link', 'author'],
  quiz: ['grade', 'subject', 'title', 'text', 'type', 'author']
};
const NEED = { homework: ['date', 'subject', 'text'], plan: ['date', 'subject', 'text'], exams: ['date', 'subject'], library: ['title', 'link'], announcement: ['date', 'title'], quiz: ['subject', 'title', 'text', 'type'] };
// السيرفر لا يرسل إلا لخدمات الإشعارات المعروفة (حماية من تسجيل روابط عشوائية)
const PUSH_HOST = /^https:\/\/(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9.-]+\.push\.services\.mozilla\.com|web\.push\.apple\.com|[a-z0-9.-]+\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com)\//;
const ipHash = async (req, env) => (await sign(env, 'ip:' + (req.headers.get('CF-Connecting-IP') || ''))).slice(0, 16);
async function vapid(env, endpoint) {
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const c = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 43200, sub: env.VAPID_SUBJECT || 'mailto:admin@example.com' })));
  const key = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + c));
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${env.VAPID_PUBLIC}`;
}
async function push(env, endpoint) {
  try { return (await fetch(endpoint, { method: 'POST', headers: { Authorization: await vapid(env, endpoint), TTL: '3600', Urgency: 'normal' } })).status; } catch { return 0; }
}
export async function onRequest({ request: req, env, params }) {
  const p = [].concat(params.path || []).join('/');
  if (!env.DB || !env.TEACHER_PASSWORD) return J({ error: 'not configured' }, 500);
  if (req.method === 'GET') {
    if (p === 'push-key') return J({ key: env.VAPID_PUBLIC || '' });
    if (p === 'latest') return J((await env.DB.prepare("SELECT kind,subject,title FROM items WHERE kind IN ('homework','announcement') ORDER BY id DESC LIMIT 1").first()) || {});
    if (p === 'data') {
      const a = await authed(req, env);
      const { results } = await env.DB.prepare("SELECT id,kind,date,grade,section,subject,title,text,coverage,link,type,author FROM items WHERE kind!='result' ORDER BY date DESC,id DESC LIMIT 2000").all();
      const o = { homework: [], plan: [], exams: [], library: [], announcement: [], quiz: [] };
      for (const r of results) {
        if (!a) delete r.author;
        if (r.kind === 'plan') { r.from = r.date; r.to = r.coverage; }
        if (r.kind === 'library') r.url = r.link;
        if (o[r.kind]) o[r.kind].push(r);
      }
      if (a) { const rr = await env.DB.prepare("SELECT id,date,grade,section,subject,title,text FROM items WHERE kind='result' ORDER BY id DESC LIMIT 1000").all(); o.result = rr.results.map(r => ({ ...r, kind: 'result' })); }
      return J(o);
    }
    return J({ error: 'not found' }, 404);
  }
  if (req.method !== 'POST') return J({ error: 'method' }, 405);
  const og = req.headers.get('Origin');
  if (og && new URL(og).host !== new URL(req.url).host) return J({ error: 'forbidden' }, 403);
  let b; try { b = await req.json(); } catch { return J({ error: 'bad request' }, 400); }
  if (p === 'login') {
    if (env.TEACHER_PASSWORD.length < 10) return J({ error: 'كلمة مرور المدرسين قصيرة. استخدم 10 أحرف على الأقل' }, 500);
    const ip = await ipHash(req, env);
    const f = await env.DB.prepare("SELECT COUNT(*) c FROM logins WHERE ip=? AND ts>datetime('now','-15 minutes')").bind(ip).first();
    if (f.c >= 8) return J({ error: 'محاولات كثيرة. حاول بعد 15 دقيقة' }, 429);
    const ok = eq(await sign(env, 'pw:' + String(b.password || '')), await sign(env, 'pw:' + env.TEACHER_PASSWORD));
    if (!ok) {
      await env.DB.batch([env.DB.prepare('INSERT INTO logins(ip) VALUES(?)').bind(ip), env.DB.prepare("DELETE FROM logins WHERE ts<datetime('now','-1 day')")]);
      await new Promise(r => setTimeout(r, 500)); return J({ error: 'كلمة المرور غير صحيحة' }, 401);
    }
    const exp = Date.now() + 30 * 864e5;
    return J({ ok: 1 }, 200, { 'Set-Cookie': `tk=${exp}.${await sign(env, String(exp))}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict` });
  }
  if (p === 'logout') return J({ ok: 1 }, 200, { 'Set-Cookie': 'tk=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict' });
  if (p === 'result') {
    const name = String(b.name || '').trim().slice(0, 60), subject = String(b.subject || '').trim().slice(0, 100), grade = String(b.grade || '').trim().slice(0, 60), section = String(b.section || '').trim().slice(0, 60);
    const sc = +b.score, tt = +b.total;
    if (!name || !subject || !Number.isInteger(sc) || !Number.isInteger(tt) || tt < 1 || tt > 50 || sc < 0 || sc > tt) return J({ error: 'بيانات غير صحيحة' }, 400);
    const ip = await ipHash(req, env);
    const r1 = await env.DB.prepare("SELECT COUNT(*) c FROM items WHERE kind='result' AND type=? AND created_at>datetime('now','-1 minute')").bind(ip).first();
    const r2 = await env.DB.prepare("SELECT COUNT(*) c FROM items WHERE kind='result' AND created_at>datetime('now','-1 hour')").first();
    if (r1.c >= 10 || r2.c >= 500) return J({ error: 'محاولات كثيرة' }, 429);
    await env.DB.prepare("INSERT INTO items(kind,date,grade,section,subject,title,text,type) VALUES('result',?,?,?,?,?,?,?)").bind(new Date().toISOString().slice(0, 10), grade, section, subject, name, sc + '/' + tt, ip).run();
    return J({ ok: 1 });
  }
  if (p === 'subscribe') {
    const ep = String(b.endpoint || '');
    if (ep.length > 600 || !PUSH_HOST.test(ep)) return J({ error: 'bad endpoint' }, 400);
    if ((await env.DB.prepare('SELECT COUNT(*) c FROM subs').first()).c >= 5000) return J({ error: 'full' }, 429);
    await env.DB.prepare('INSERT INTO subs(endpoint,grade) VALUES(?,?) ON CONFLICT(endpoint) DO UPDATE SET grade=excluded.grade').bind(ep, String(b.grade || '').slice(0, 60)).run();
    return J({ ok: 1 });
  }
  if (p === 'unsubscribe') { await env.DB.prepare('DELETE FROM subs WHERE endpoint=?').bind(String(b.endpoint || '')).run(); return J({ ok: 1 }); }
  if (!(await authed(req, env))) return J({ error: 'unauthorized' }, 401);
  if (p === 'me') return J({ ok: 1 });
  if (p === 'notify') {
    if (!env.VAPID_PRIVATE || !env.VAPID_PUBLIC) return J({ error: 'push not configured' }, 501);
    if (!['homework', 'announcement'].includes(b.kind)) return J({ error: 'bad kind' }, 400);
    const after = +b.after || 0, grade = String(b.grade || '').slice(0, 60);
    const st = b.kind === 'homework' && grade
      ? env.DB.prepare("SELECT id,endpoint FROM subs WHERE id>? AND (grade='' OR grade=?) ORDER BY id LIMIT 40").bind(after, grade)
      : env.DB.prepare('SELECT id,endpoint FROM subs WHERE id>? ORDER BY id LIMIT 40').bind(after);
    const { results } = await st.all();
    const codes = await Promise.all(results.map(r => push(env, r.endpoint)));
    const dead = results.filter((r, i) => codes[i] === 404 || codes[i] === 410).map(r => r.id);
    if (dead.length) await env.DB.prepare(`DELETE FROM subs WHERE id IN (${dead.map(() => '?').join(',')})`).bind(...dead).run();
    return J({ ok: 1, sent: results.length - dead.length, next: results.length === 40 ? results[39].id : null });
  }
  if (p === 'planimport') {
    const subject = String(b.subject || '').trim().slice(0, 100), grade = String(b.grade || '').trim().slice(0, 60), section = String(b.section || '').trim().slice(0, 60);
    const w = Array.isArray(b.weeks) ? b.weeks : [];
    if (!subject) return J({ error: 'اختر المادة' }, 400);
    if (!w.length || w.length > 60) return J({ error: 'عدد الأسابيع غير صحيح' }, 400);
    const DT = /^\d{4}-\d{2}-\d{2}$/, rows = [];
    for (const x of w) {
      const f = String(x.from || ''), t = String(x.to || ''), tx = String(x.text || '').trim().slice(0, 1000);
      if (!DT.test(f) || !DT.test(t) || !tx) return J({ error: 'بيانات أسبوع غير صحيحة' }, 400);
      rows.push([f, t, grade, section, subject, tx]);
    }
    const st = [env.DB.prepare("DELETE FROM items WHERE kind='plan' AND subject=? AND COALESCE(grade,'')=? AND COALESCE(section,'')=?").bind(subject, grade, section)];
    for (let i = 0; i < rows.length; i += 12) { const c = rows.slice(i, i + 12); st.push(env.DB.prepare("INSERT INTO items(kind,date,coverage,grade,section,subject,text) VALUES " + c.map(() => "('plan',?,?,?,?,?,?)").join(',')).bind(...c.flat())); }
    await env.DB.batch(st);
    return J({ ok: 1, n: rows.length });
  }
  if (p === 'plandelete') {
    await env.DB.prepare("DELETE FROM items WHERE kind='plan' AND subject=? AND COALESCE(grade,'')=? AND COALESCE(section,'')=?").bind(String(b.subject || ''), String(b.grade || ''), String(b.section || '')).run();
    return J({ ok: 1 });
  }
  if (p === 'save') {
    const k = b.kind, f = F[k];
    if (!f) return J({ error: 'bad kind' }, 400);
    const v = {}; f.forEach(x => v[x] = String(b[x] || '').trim().slice(0, 1000));
    if (NEED[k].some(x => !v[x])) return J({ error: 'بيانات ناقصة' }, 400);
    if (k === 'quiz') { const op = v.text.split('|').map(x => x.trim()).filter(Boolean); if (op.length < 2 || op.length > 4 || !(+v.type >= 1 && +v.type <= op.length)) return J({ error: 'الخيارات أو رقم الإجابة غير صحيح' }, 400); v.text = op.join('|'); v.type = String(+v.type); }
    if (v.date !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(v.date)) return J({ error: 'تاريخ غير صحيح' }, 400);
    if (v.link && !/^https?:\/\//i.test(v.link)) return J({ error: 'الرابط لازم يبدأ بـ https://' }, 400);
    await env.DB.prepare(`INSERT INTO items(kind,${f.join(',')}) VALUES(?${',?'.repeat(f.length)})`).bind(k, ...f.map(x => v[x])).run();
    return J({ ok: 1 });
  }
  if (p === 'delete') { await env.DB.prepare('DELETE FROM items WHERE id=?').bind(+b.id).run(); return J({ ok: 1 }); }
  if (p === 'purge') {
    const ks = (b.kinds || []).filter(k => F[k] || k === 'result');
    if (!ks.length || !/^\d{4}-\d{2}-\d{2}$/.test(b.before || '')) return J({ error: 'بيانات ناقصة' }, 400);
    const r = await env.DB.prepare(`DELETE FROM items WHERE kind IN (${ks.map(() => '?').join(',')}) AND COALESCE(date,substr(created_at,1,10))<?`).bind(...ks, b.before).run();
    return J({ ok: 1, n: r.meta.changes });
  }
  return J({ error: 'not found' }, 404);
}

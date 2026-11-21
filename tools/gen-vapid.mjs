// تشغيل: node tools/gen-vapid.mjs
import { webcrypto as crypto } from 'node:crypto';
const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const pub = Buffer.from(await crypto.subtle.exportKey('raw', k.publicKey)).toString('base64url');
const jwk = await crypto.subtle.exportKey('jwk', k.privateKey);
console.log('VAPID_PUBLIC  (متغير عادي) =', pub);
console.log('VAPID_PRIVATE (Secret، سري، لا تشاركه) =', JSON.stringify(jwk));
console.log('VAPID_SUBJECT (متغير عادي) = mailto:your-email@example.com');

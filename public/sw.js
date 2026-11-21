self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('push',e=>{
  e.waitUntil(fetch('/api/latest',{cache:'no-store'}).then(r=>r.json()).catch(()=>({})).then(d=>{
    const body=d.kind==='homework'?'واجب جديد: '+(d.subject||''):d.kind==='announcement'?'إعلان: '+(d.title||''):'يوجد تحديث جديد في البوابة';
    return self.registration.showNotification('بوابة أولياء الأمور',{body,icon:'/icon-192.png',badge:'/icon-192.png',tag:'portal-update',lang:'ar',dir:'rtl'});
  }));
});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('focus' in c)return c.focus()}return self.clients.openWindow('/')}))});

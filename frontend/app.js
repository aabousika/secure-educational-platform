/* app.js — FastAPI client + role-based dashboards (vanilla JS, no dependencies).
 * Security: server data is rendered only via textContent / text nodes, never innerHTML.
 * The JWT lives in sessionStorage (cleared when the tab closes); the server re-validates every request. */
'use strict';
(() => {
  const DEFAULT_API = 'http://127.0.0.1:8000';
  const ROOT = document.body.dataset.root || '';   // "" for root pages, "../" for pages/
  const VIEW = document.body.dataset.view || 'auto'; // auto | login | student | teacher | admin
  const ROLE_AR = { student: 'طالب', instructor: 'مدرّس' };
  const STATUS_AR = {
    400: 'طلب غير صالح', 401: 'البريد الإلكتروني أو كلمة المرور غير صحيحة',
    403: 'ليست لديك صلاحية لهذا الإجراء', 404: 'العنصر المطلوب غير موجود',
    409: 'البيانات مكرّرة أو متعارضة', 422: 'تحقق من صحة الحقول المُدخلة',
    429: 'محاولات كثيرة، حاول لاحقًا', 500: 'خطأ داخلي في الخادم',
  };
  const apiBase = () => (localStorage.getItem('api_base') || DEFAULT_API).replace(/\/+$/, '');
  const home = () => ROOT + 'index.html';

  /* ---------------- DOM helpers ---------------- */
  const h = (tag, attrs, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid);
    return el;
  };
  const field = (label, attrs, tag = 'input') => h('label', { class: 'field' }, h('span', {}, label), h(tag, attrs));
  const card = (title, ...kids) => h('section', { class: 'card' }, title ? h('h3', {}, title) : null, ...kids);
  const ltr = (txt, cls = '') => h('span', { class: ('ltr ' + cls).trim() }, txt);
  const stat = (label, value) => h('div', { class: 'stat' }, h('small', {}, label), h('strong', {}, value));
  const kv = pairs => h('dl', { class: 'kv' }, pairs.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));

  const fmtNum = n => Number(n).toLocaleString('en-US', { maximumFractionDigits: 2 });
  const dateFmt = new Intl.DateTimeFormat('ar-u-nu-latn', { dateStyle: 'medium', timeStyle: 'short' });
  const fmtDate = v => { const d = new Date(v); return isNaN(d) ? String(v) : dateFmt.format(d); };
  const pct = (s, m) => (m > 0 ? Math.round((s / m) * 1000) / 10 : 0);
  // IDs are typed as free text: digits only, within the PostgreSQL SERIAL (int32) range.
  const parseId = v => {
    const s = String(v).trim();
    if (!/^\d+$/.test(s) || Number(s) < 1 || Number(s) > 2147483647) throw new Error('أدخل رقمًا صحيحًا موجبًا (أرقام فقط)');
    return Number(s);
  };

  function toast(msg, type = 'ok') {
    let box = document.getElementById('toasts');
    if (!box) { box = h('div', { id: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(box); }
    const t = h('div', { class: 'toast ' + type }, msg);
    box.append(t);
    setTimeout(() => t.remove(), 4500);
  }

  /* ---------------- session ---------------- */
  const Session = {
    get token() { return sessionStorage.getItem('token'); },
    get email() { return sessionStorage.getItem('email') || ''; },
    set(token, email) { sessionStorage.setItem('token', token); sessionStorage.setItem('email', email); },
    clear() { sessionStorage.removeItem('token'); sessionStorage.removeItem('email'); },
    // Claims are decoded for display/routing only — authorization is enforced by the backend.
    user() {
      try {
        const b64 = this.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const c = JSON.parse(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)));
        if (!c.sub || (c.exp && c.exp * 1000 <= Date.now())) return null;
        return { id: Number(c.sub), role: c.role, exp: c.exp };
      } catch { return null; }
    },
  };
  function logout(reason) {
    Session.clear();
    if (reason) sessionStorage.setItem('flash', reason);
    location.replace(home());
  }

  /* ---------------- API client ---------------- */
  class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

  function errorText(status, detail) {
    const base = STATUS_AR[status] || `خطأ غير متوقع (${status})`;
    if (Array.isArray(detail)) // FastAPI/Pydantic 422
      return `${base}: ` + detail.map(d => `${(d.loc || []).slice(1).join('.')} — ${d.msg}`).join('؛ ');
    if (typeof detail === 'string' && [400, 404, 409].includes(status)) return `${base} (${detail})`;
    return base;
  }

  async function api(path, { method = 'GET', body, form, auth = true } = {}) {
    const headers = {};
    let payload;
    if (auth) headers.Authorization = `Bearer ${Session.token}`;
    if (form) payload = new URLSearchParams(form);             // /auth/login expects OAuth2 form encoding
    else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    let res;
    try { res = await fetch(apiBase() + path, { method, headers, body: payload }); }
    catch { throw new ApiError(0, `تعذّر الاتصال بالخادم (${apiBase()}). تأكد من تشغيل FastAPI ومن إعداد CORS_ORIGINS.`); }
    if (res.status === 204) return null;
    const data = await res.json().catch(() => null);
    if (res.ok) return data;
    if (res.status === 401 && auth) logout('انتهت الجلسة، يرجى تسجيل الدخول مجددًا.');
    throw new ApiError(res.status, errorText(res.status, data && data.detail));
  }
  const fetchPII = id => api(`/students/${id}/pii`).catch(e => (e.status === 404 ? null : Promise.reject(e)));

  /* ---------------- reusable UI pieces ---------------- */
  function loadInto(box, fn, render) {
    box.replaceChildren(h('p', { class: 'muted' }, 'جارٍ التحميل…'));
    fn().then(d => box.replaceChildren(render(d)))
      .catch(e => box.replaceChildren(h('p', { class: 'error' }, e.message),
        h('button', { class: 'btn', type: 'button', onclick: () => loadInto(box, fn, render) }, 'إعادة المحاولة')));
  }

  function formEl(fields, submitLabel, onSubmit, cls = 'stack') {
    const msg = h('p', { class: 'form-msg', role: 'alert' });
    const btn = h('button', { class: 'btn primary', type: 'submit' }, submitLabel);
    const form = h('form', { class: cls }, ...fields, msg, btn);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (!form.reportValidity()) return;
      msg.textContent = ''; btn.disabled = true;
      try { await onSubmit(new FormData(form), form); }
      catch (err) { msg.textContent = err.message; }
      finally { btn.disabled = false; }
    });
    return form;
  }

  function tabs(items, initial = 0) {
    const nav = h('div', { class: 'tabs', role: 'tablist' });
    const box = h('div', { role: 'tabpanel' });
    const built = new Map();
    const buttons = items.map((it, i) => {
      const b = h('button', { class: 'tab', role: 'tab', type: 'button', onclick: () => show(i) }, it.label);
      nav.append(b);
      return b;
    });
    function show(i) {
      buttons.forEach((b, j) => b.setAttribute('aria-selected', String(i === j)));
      if (!built.has(i)) built.set(i, items[i].render());
      box.replaceChildren(built.get(i));
    }
    show(initial);
    return h('div', {}, nav, box);
  }

  const bar = p => {
    const fill = h('i'); fill.style.width = Math.min(100, p) + '%';
    return h('div', { class: 'bar', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': p },
      h('b', {}, fill), h('em', {}, p + '%'));
  };

  function gradesTable(rows) {
    if (!rows.length) return h('p', { class: 'muted' }, 'لا توجد درجات مسجّلة بعد.');
    const avg = rows.reduce((a, g) => a + pct(g.score, g.max_score), 0) / rows.length;
    return h('div', {},
      h('div', { class: 'stats' }, stat('عدد المقررات', rows.length), stat('المعدل العام', avg.toFixed(1) + '%')),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['المقرر', 'الدرجة', 'النسبة', 'آخر تحديث'].map(t => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, rows.map(g => h('tr', {},
          h('td', {}, g.course),
          h('td', {}, ltr(`${fmtNum(g.score)} / ${fmtNum(g.max_score)}`)),
          h('td', {}, bar(pct(g.score, g.max_score))),
          h('td', {}, fmtDate(g.updated_at))))))));
  }

  const piiView = d => !d
    ? h('p', { class: 'muted' }, 'لم تُسجَّل بيانات شخصية بعد.')
    : kv([['العنوان', d.address], ['رقم الهاتف', ltr(d.phone_number)], ['تاريخ الميلاد', ltr(d.date_of_birth)]]);

  function certCard(c) {
    const badge = h('span', { class: 'badge ' + (c.valid ? 'ok' : 'bad') }, c.valid ? 'صالحة' : 'غير صالحة');
    const btn = h('button', { class: 'btn', type: 'button', onclick: async () => {
      btn.disabled = true;
      try {
        const r = await api(`/certificates/verify/${c.id}`, { method: 'POST' });
        badge.className = 'badge ' + (r.valid ? 'ok' : 'bad');
        badge.textContent = r.valid ? 'صالحة' : 'غير صالحة';
        toast(r.valid ? 'التوقيع الرقمي سليم' : 'فشل التحقق: الشهادة غير صالحة', r.valid ? 'ok' : 'err');
      } catch (e) { toast(e.message, 'err'); } finally { btn.disabled = false; }
    } }, 'التحقق من التوقيع الرقمي');
    return h('article', { class: 'card' },
      h('div', { class: 'row' }, h('h3', { style: 'margin:0' }, c.course), badge),
      kv([['رقم الشهادة', ltr('#' + c.id)], ['رقم الطالب', ltr('#' + c.student_id)], ['تاريخ الإصدار', fmtDate(c.issued_at)]]),
      h('details', {}, h('summary', {}, 'التفاصيل التشفيرية'),
        kv([['SHA-256', ltr(c.digest_sha256, 'mono')], ['Ed25519 (Base64)', ltr(c.signature_b64, 'mono')], ['Payload', ltr(c.payload, 'mono')]])),
      btn);
  }

  /* ---------------- student views ---------------- */
  function studentView(user) {
    return tabs([
      { label: 'الدرجات', render: () => { const b = h('div'); loadInto(b, () => api('/grades/me'), gradesTable); return card('درجاتي', b); } },
      { label: 'الشهادات', render: () => {
        const b = h('div');
        loadInto(b, () => api('/certificates/me'), list => list.length
          ? h('div', { class: 'stack' }, list.map(c => certCard(c)))
          : h('p', { class: 'muted' }, 'لا توجد شهادات صادرة لك بعد.'));
        return b;
      } },
      { label: 'البيانات الشخصية', render: () => { const b = h('div'); loadInto(b, () => fetchPII(user.id), piiView); return card('بياناتي الشخصية (مشفّرة في قاعدة البيانات)', b); } },
    ]);
  }

  /* ---------------- instructor views ---------------- */
  function gradesAdmin(id) {
    const box = h('div');
    const refresh = () => loadInto(box, () => api(`/grades/student/${id}`), gradesTable);
    const form = formEl([
      h('div', { class: 'row-form' },
        field('المقرر', { name: 'course', required: true, maxlength: 160 }),
        field('الدرجة', { name: 'score', type: 'number', min: 0, step: 'any', required: true, dir: 'ltr' }),
        field('الدرجة العظمى', { name: 'max_score', type: 'number', min: 0, max: 1000, step: 'any', value: 100, required: true, dir: 'ltr' })),
    ], 'إضافة الدرجة', async (fd, f) => {
      const score = Number(fd.get('score')), max = Number(fd.get('max_score'));
      if (!(max > 0) || score < 0 || score > max) throw new Error('يجب أن تكون الدرجة بين صفر والدرجة العظمى');
      await api('/grades', { method: 'POST', body: { student_id: id, course: fd.get('course').trim(), score, max_score: max } });
      toast('تمت إضافة الدرجة'); f.reset(); refresh();
    });
    refresh();
    return h('div', { class: 'stack' }, card('إضافة درجة', form), card('درجات الطالب', box));
  }

  function piiAdmin(id) {
    const box = h('div');
    const keys = ['address', 'phone_number', 'date_of_birth'];
    const form = formEl([
      field('العنوان', { name: 'address', required: true, maxlength: 500, rows: 3 }, 'textarea'),
      field('رقم الهاتف', { name: 'phone_number', type: 'tel', required: true, minlength: 3, maxlength: 40, dir: 'ltr' }),
      field('تاريخ الميلاد', { name: 'date_of_birth', type: 'date', required: true }),
    ], 'حفظ (يُشفَّر قبل التخزين)', async fd => {
      await api(`/students/${id}/pii`, { method: 'PUT', body: {
        address: fd.get('address').trim(), phone_number: fd.get('phone_number').trim(), date_of_birth: fd.get('date_of_birth') } });
      toast('تم حفظ البيانات الشخصية'); refresh();
    });
    const refresh = () => loadInto(box, () => fetchPII(id), d => {
      if (d) keys.forEach(k => { form.elements[k].value = d[k]; });
      return piiView(d);
    });
    refresh();
    return h('div', { class: 'stack' }, card('البيانات المسجّلة', box), card('إدخال / تعديل', form));
  }

  function issueCert(id) {
    const out = h('div');
    const form = formEl([field('اسم المقرر', { name: 'course', required: true, maxlength: 160 })],
      'إصدار شهادة موقّعة', async (fd, f) => {
        const c = await api('/certificates', { method: 'POST', body: { student_id: id, course: fd.get('course').trim() } });
        toast('تم إصدار الشهادة'); out.replaceChildren(certCard(c)); f.reset();
      });
    return h('div', { class: 'stack' }, card('إصدار شهادة', form), out);
  }

  function teacherView() {
    const out = h('div');
    const form = formEl([field('رقم الطالب (ID)', { name: 'sid', type: 'text', inputmode: 'numeric', pattern: '[0-9]+', title: 'أرقام فقط', autocomplete: 'off', required: true, dir: 'ltr' })],
      'فتح ملف الطالب', fd => {
        const id = parseId(fd.get('sid'));
        out.replaceChildren(h('div', { class: 'stack' }, h('h2', {}, `ملف الطالب #${id}`), tabs([
          { label: 'الدرجات', render: () => gradesAdmin(id) },
          { label: 'البيانات الشخصية', render: () => piiAdmin(id) },
          { label: 'إصدار شهادة', render: () => issueCert(id) },
        ])));
      }, 'row-form');
    return h('div', { class: 'stack' },
      card('البحث عن طالب', form, h('p', { class: 'note' }, 'يظهر رقم الطالب في أعلى الصفحة بعد تسجيل دخوله (بجوار الدور).')), out);
  }

  function adminView(user) {
    const health = h('div');
    const check = () => loadInto(health, () => api('/health', { auth: false }),
      d => h('p', {}, h('span', { class: 'badge ' + (d.status === 'ok' ? 'ok' : 'bad') }, d.status === 'ok' ? 'الخادم يعمل' : d.status), ' ', ltr(apiBase())));
    check();

    const apiForm = formEl([field('عنوان الـ API', { name: 'url', type: 'url', required: true, value: apiBase(), dir: 'ltr' })],
      'حفظ العنوان', fd => {
        const u = new URL(fd.get('url'));
        if (!/^https?:$/.test(u.protocol)) throw new Error('يجب أن يبدأ العنوان بـ http أو https');
        localStorage.setItem('api_base', u.origin);
        toast('تم حفظ العنوان'); check();
      }, 'row-form');

    const out = h('div');
    const certForm = formEl([field('رقم الشهادة', { name: 'cid', type: 'text', inputmode: 'numeric', pattern: '[0-9]+', title: 'أرقام فقط', autocomplete: 'off', required: true, dir: 'ltr' })],
      'عرض والتحقق', async fd => {
        out.replaceChildren(certCard(await api(`/certificates/${parseId(fd.get('cid'))}`)));
      }, 'row-form');

    return h('div', { class: 'stack' },
      card('حالة الخادم', health, apiForm),
      card('التحقق من شهادة', certForm, out),
      card('الجلسة الحالية', kv([['رقم الحساب', ltr('#' + user.id)], ['الدور', ROLE_AR[user.role] || user.role], ['تنتهي الجلسة', fmtDate(user.exp * 1000)]])),
      h('p', { class: 'note' }, 'ملاحظة: لا يوجد دور «مدير» في الـ Backend الحالي؛ هذه الصفحة للمدرّسين. إنشاء حساب مدرّس يتم عبر سطر الأوامر فقط: ',
        h('code', { class: 'ltr' }, 'python -m app.presentation.cli create-instructor')));
  }

  /* ---------------- auth screen ---------------- */
  async function login(email, password) {
    const d = await api('/auth/login', { method: 'POST', auth: false, form: { username: email, password } });
    Session.set(d.access_token, email);
    location.replace(home());
  }

  function renderAuth(root) {
    const flash = sessionStorage.getItem('flash'); sessionStorage.removeItem('flash');
    const loginForm = formEl([
      field('البريد الإلكتروني', { name: 'email', type: 'email', required: true, autocomplete: 'username', dir: 'ltr' }),
      field('كلمة المرور', { name: 'password', type: 'password', required: true, autocomplete: 'current-password', dir: 'ltr' }),
    ], 'تسجيل الدخول', fd => login(fd.get('email').trim(), fd.get('password')));

    const regForm = formEl([
      field('الاسم الكامل', { name: 'full_name', required: true, minlength: 2, maxlength: 120, autocomplete: 'name' }),
      field('البريد الإلكتروني', { name: 'email', type: 'email', required: true, autocomplete: 'email', dir: 'ltr' }),
      field('كلمة المرور (12 حرفًا على الأقل)', { name: 'password', type: 'password', required: true, minlength: 12, maxlength: 128, autocomplete: 'new-password', dir: 'ltr' }),
      field('تأكيد كلمة المرور', { name: 'confirm', type: 'password', required: true, minlength: 12, autocomplete: 'new-password', dir: 'ltr' }),
    ], 'إنشاء حساب طالب', async fd => {
      if (fd.get('password') !== fd.get('confirm')) throw new Error('كلمتا المرور غير متطابقتين');
      const email = fd.get('email').trim();
      await api('/auth/register', { method: 'POST', auth: false, body: { full_name: fd.get('full_name').trim(), email, password: fd.get('password') } });
      await login(email, fd.get('password'));
    });

    const fileWarn = location.protocol === 'file:'
      ? 'تنبيه: افتح الواجهة عبر خادم محلي (python -m http.server 3000) وليس مباشرة من الملف، وإلا سيمنع CORS الطلبات.' : null;
    root.replaceChildren(h('div', { class: 'auth' },
      h('h1', {}, '🎓 المنصة التعليمية الآمنة'),
      flash ? h('p', { class: 'note' }, flash) : null,
      fileWarn ? h('p', { class: 'note' }, fileWarn) : null,
      card(null, tabs([{ label: 'تسجيل الدخول', render: () => loginForm }, { label: 'حساب طالب جديد', render: () => regForm }]))));
  }

  /* ---------------- shell + routing ---------------- */
  function shell(user, body) {
    return h('div', {},
      h('header', { class: 'app-header' }, h('div', { class: 'in' },
        h('a', { class: 'brand', href: home() }, '🎓 المنصة التعليمية الآمنة'),
        h('span', { class: 'chip' }, `${ROLE_AR[user.role] || user.role} · #${user.id}`),
        Session.email ? h('span', { class: 'chip' }, ltr(Session.email)) : null,
        h('button', { class: 'btn', type: 'button', onclick: () => logout() }, 'تسجيل الخروج'))),
      h('main', { class: 'container' }, body));
  }

  const denied = () => card(null, h('p', { class: 'error' }, 'ليست لديك صلاحية لعرض هذه الصفحة.'),
    h('a', { class: 'btn', href: home() }, 'العودة للرئيسية'));

  function mount() {
    const root = document.getElementById('app');
    const user = Session.user();
    if (!user) {
      Session.clear();
      if (VIEW === 'auto' || VIEW === 'login') return renderAuth(root);
      return location.replace(home());
    }
    if (VIEW === 'login') return location.replace(home());

    const isInstr = user.role === 'instructor', isStud = user.role === 'student';
    let body;
    if (VIEW === 'student') body = isStud ? studentView(user) : denied();
    else if (VIEW === 'teacher') body = isInstr ? teacherView() : denied();
    else if (VIEW === 'admin') body = isInstr ? adminView(user) : denied();
    else if (isStud) body = studentView(user);
    else if (isInstr) body = tabs([{ label: 'الطلاب والدرجات', render: teacherView }, { label: 'الإدارة والتحقق', render: () => adminView(user) }]);
    else body = denied();
    root.replaceChildren(shell(user, body));

    const ms = user.exp * 1000 - Date.now();   // auto-logout when the token expires
    if (ms > 0) setTimeout(() => logout('انتهت الجلسة، يرجى تسجيل الدخول مجددًا.'), Math.min(ms, 2 ** 31 - 1));
  }

  mount();
})();

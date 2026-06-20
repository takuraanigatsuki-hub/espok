(function () {
  'use strict';

  const API = 'api';
  const PERSONAS = [
    ['INV_MVD', 'Следователь МВД'],
    ['INV_LEAD_MVD', 'Руководитель следствия'],
    ['INV_SK', 'Следователь СК'],
    ['TECH_ADMIN', 'Тех. админ'],
    ['FUNC_ADMIN', 'Функ. админ ИТ'],
    ['BETA_TAKURA', 'Бета · полный доступ'],
    ['PROSEC', 'Прокурор'],
    ['ANALYST', 'Аналитик'],
    ['EXEC_MVD', 'Исполнитель МВД'],
    ['EXEC_FNS', 'Исполнитель ФНС'],
    ['EXEC_RFM', 'Росфинмониторинг'],
  ];

  const loginView = document.getElementById('login-view');
  const appView = document.getElementById('app-view');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');
  const adminLabel = document.getElementById('admin-label');
  const usersTbody = document.getElementById('users-tbody');
  const auditTbody = document.getElementById('audit-tbody');
  const userModal = document.getElementById('user-modal');
  const userForm = document.getElementById('user-form');
  const userFormError = document.getElementById('user-form-error');
  const personaSelect = document.getElementById('f-persona');
  const toastEl = document.getElementById('toast');

  let editingId = null;

  PERSONAS.forEach(([id, label]) => {
    const opt = document.createElement('option');
    opt.value = id;
    opt.textContent = `${id} · ${label}`;
    personaSelect.appendChild(opt);
  });

  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toastEl.classList.add('hidden'), 2800);
  }

  async function api(path, opts = {}) {
    const res = await fetch(`${API}${path}`, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function showApp(admin) {
    loginView.classList.remove('active');
    appView.classList.add('active');
    adminLabel.textContent = admin.displayName || admin.username;
  }

  function showLogin() {
    appView.classList.remove('active');
    loginView.classList.add('active');
  }

  async function checkSession() {
    try {
      const data = await api('/admin/users.php?action=me');
      if (data.authenticated) {
        showApp(data.admin);
        await refreshUsers();
        return true;
      }
    } catch (_) { /* not logged in */ }
    showLogin();
    return false;
  }

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');
    const username = document.getElementById('login-user').value.trim().toLowerCase();
    const password = document.getElementById('login-pass').value;
    try {
      const data = await api('/admin/login.php', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      showApp(data.admin);
      await refreshUsers();
      toast('Вход выполнен');
    } catch (err) {
      loginError.textContent = err.message || 'Ошибка входа';
      loginError.classList.remove('hidden');
    }
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
      await api('/admin/logout.php', { method: 'POST', body: '{}' });
    } catch (_) { /* ignore */ }
    showLogin();
  });

  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`panel-${btn.dataset.panel}`).classList.add('active');
      if (btn.dataset.panel === 'audit') await refreshAudit();
    });
  });

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  }

  async function refreshUsers() {
    const data = await api('/admin/users.php');
    usersTbody.innerHTML = data.users.map(u => `
      <tr>
        <td><code>${esc(u.username)}</code></td>
        <td>${esc(u.displayName)}</td>
        <td><code>${esc(u.personaId)}</code></td>
        <td><span class="tag ${u.isActive ? 'ok' : 'off'}">${u.isActive ? 'да' : 'нет'}</span></td>
        <td>${u.isSuperadmin ? '⛨' : '—'}</td>
        <td><button type="button" class="btn-sm" data-edit="${u.id}">Изменить</button></td>
      </tr>`).join('');
    usersTbody.querySelectorAll('[data-edit]').forEach(btn => {
      btn.addEventListener('click', () => openEdit(Number(btn.dataset.edit), data.users));
    });
  }

  async function refreshAudit() {
    const data = await api('/admin/audit.php');
    auditTbody.innerHTML = data.entries.map(e => `
      <tr>
        <td>${esc(e.created_at)}</td>
        <td>${esc(e.actor_username)}</td>
        <td>${esc(e.action)}</td>
        <td>${esc(e.target_ref || '—')}</td>
        <td>${esc(e.ip_address || '—')}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="muted">Записей нет</td></tr>';
  }

  function openCreate() {
    editingId = null;
    document.getElementById('user-modal-title').textContent = 'Новый пользователь';
    document.getElementById('f-username').disabled = false;
    document.getElementById('f-username').value = '';
    document.getElementById('f-password').value = '';
    document.getElementById('f-password').required = true;
    document.getElementById('f-display').value = '';
    document.getElementById('f-contour').value = '';
    document.getElementById('f-persona').value = 'INV_MVD';
    document.getElementById('f-switch').checked = false;
    document.getElementById('f-active').checked = true;
    document.getElementById('f-super').checked = false;
    userFormError.classList.add('hidden');
    userModal.classList.remove('hidden');
  }

  function openEdit(id, users) {
    const u = users.find(x => x.id === id);
    if (!u) return;
    editingId = id;
    document.getElementById('user-modal-title').textContent = `Изменить · ${u.username}`;
    document.getElementById('f-username').value = u.username;
    document.getElementById('f-username').disabled = true;
    document.getElementById('f-password').value = '';
    document.getElementById('f-password').required = false;
    document.getElementById('f-display').value = u.displayName;
    document.getElementById('f-contour').value = u.contourLabel || '';
    document.getElementById('f-persona').value = u.personaId;
    document.getElementById('f-switch').checked = u.canSwitchPersona;
    document.getElementById('f-active').checked = u.isActive;
    document.getElementById('f-super').checked = u.isSuperadmin;
    userFormError.classList.add('hidden');
    userModal.classList.remove('hidden');
  }

  document.getElementById('new-user-btn').addEventListener('click', openCreate);
  document.getElementById('user-cancel').addEventListener('click', () => userModal.classList.add('hidden'));

  userForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    userFormError.classList.add('hidden');
    const payload = {
      displayName: document.getElementById('f-display').value.trim(),
      contourLabel: document.getElementById('f-contour').value.trim(),
      personaId: document.getElementById('f-persona').value,
      canSwitchPersona: document.getElementById('f-switch').checked,
      isActive: document.getElementById('f-active').checked,
      isSuperadmin: document.getElementById('f-super').checked,
    };
    const password = document.getElementById('f-password').value;
    if (password) payload.password = password;

    try {
      if (editingId) {
        await api(`/admin/users.php?id=${editingId}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        });
        toast('Пользователь обновлён');
      } else {
        payload.username = document.getElementById('f-username').value.trim().toLowerCase();
        if (!payload.password) {
          userFormError.textContent = 'Укажите пароль (мин. 8 символов)';
          userFormError.classList.remove('hidden');
          return;
        }
        await api('/admin/users.php', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        toast('Пользователь создан');
      }
      userModal.classList.add('hidden');
      await refreshUsers();
    } catch (err) {
      userFormError.textContent = err.message || 'Ошибка сохранения';
      userFormError.classList.remove('hidden');
    }
  });

  checkSession();
})();

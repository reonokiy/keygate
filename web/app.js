'use strict';
const $ = s => document.querySelector(s);
const status = $('#status');
async function api(path, method = 'GET', body) {
  const response = await fetch(path, {method, credentials: 'same-origin', headers: {'Content-Type':'application/json','X-Keygate-CSRF':'1'}, body: body ? JSON.stringify(body) : undefined});
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || `请求失败 (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}
function node(tag, text, cls) { const e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }
async function action(button, callback) {
  button.disabled = true; status.textContent = '';
  try { await callback(); } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
}
async function refresh() {
  const apps = await api('/api/apps');
  $('#apps').replaceChildren();
  if (!apps.length) $('#apps').append(node('p','还没有共享应用。创建应用后，每位用户都能为它生成自己的 API key。','empty'));
  for (const app of apps) {
    const card = node('article',null,'card'); card.append(node('h2',app.name),node('code',app.id));
    const form = node('form'); form.className = 'row key-form';
    const input = node('input'); input.placeholder = '调用方名称，例如：我的脚本'; input.required = true; input.maxLength = 128; input.setAttribute('aria-label','密钥名称');
    const button = node('button','生成密钥'); form.append(input,button);
    form.addEventListener('submit',e => { e.preventDefault(); action(button,async () => {
      const result = await api(`/api/apps/${app.id}/keys`,'POST',{name:input.value});
      $('#new-key').value = result.key; $('#key-dialog').showModal(); input.value = ''; await refresh();
    }); }); card.append(form);
    card.append(node('h3','我的 API key'));
    if (!app.keys.length) card.append(node('p','你还没有为这个应用生成 API key。','empty'));
    const list = node('ul');
    for (const key of app.keys) {
      const li = node('li'); const info = node('div'); info.append(node('strong',key.name),node('small',`${new Date(key.created_at*1000).toLocaleString()} · ${key.revoked ? '已撤销' : '有效'}`)); li.append(info);
      if (!key.revoked) {
        const revoke = node('button','撤销','danger'); revoke.type = 'button';
        revoke.addEventListener('click',() => { if (confirm(`撤销“${key.name}”？此操作不可恢复。`)) action(revoke,async () => { await api(`/api/apps/${app.id}/keys/${key.id}`,'DELETE'); await refresh(); }); });
        li.append(revoke);
      } list.append(li);
    } card.append(list); $('#apps').append(card);
  }
}
$('#create-app').addEventListener('submit', e => {e.preventDefault(); action(e.currentTarget.querySelector('button'),async () => { await api('/api/apps','POST',{name:$('#app-name').value}); $('#app-name').value = ''; await refresh(); });});
function clearKey() { $('#new-key').value = ''; $('#copy-key').textContent = '复制密钥'; }
$('#close-key').addEventListener('click',() => { clearKey(); $('#key-dialog').close(); });
$('#key-dialog').addEventListener('cancel',clearKey);
$('#key-dialog').addEventListener('close',clearKey);
$('#copy-key').addEventListener('click',async () => { try { await navigator.clipboard.writeText($('#new-key').value); $('#copy-key').textContent = '已复制'; } catch { $('#new-key').select(); } });
(async () => { try { const me = await api('/api/me'); $('#identity').textContent = me.subject; await refresh(); } catch (error) { status.textContent = error.message; } })();

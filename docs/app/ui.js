window.ruProxies = [];
window.foreignProxies = [];

async function parseServersText(text, prefix) {
  if (!text) return [];
  try {
    const wgProxies = parseWireGuardConfig(text);
    if (wgProxies && wgProxies.length > 0) {
      return wgProxies.map((p, i) => {
        const displayType = p['amnezia-wg-option'] ? `awg ${p.awgVersion || ''}`.trim() : p.type;
        p.name = `${prefix} ${i + 1} (${displayType})`;
        return p;
      });
    }
  } catch(e) {}

  const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  const proxies = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    try {
      const parsed = await parseProxyUrl(line);
      if (parsed) {
        const displayType = parsed['amnezia-wg-option'] ? `awg ${parsed.awgVersion || ''}`.trim() : parsed.type;
        parsed.name = `${prefix} ${i + 1} (${displayType})`;
        proxies.push(parsed);
      }
    } catch (e) {
      console.warn('Failed to parse line:', line);
    }
  }
  return proxies;
}

window.addServers = async function(type) {
  const inputEl = document.getElementById(`${type}-servers-input`);
  const text = inputEl.value;
  if (!text.trim()) {
    showToast('Введите текст или ссылки для парсинга', 'error');
    return;
  }
  
  const prefix = type === 'ru' ? 'Сбер' : 'Global';
  const newProxies = await parseServersText(text, prefix);
  
  if (newProxies.length === 0) {
    showToast('Не удалось распознать серверы', 'error');
    return;
  }
  
  const targetArray = type === 'ru' ? window.ruProxies : window.foreignProxies;
  // Перенумеруем, чтобы не было конфликтов имен, если добавили несколько раз
  newProxies.forEach(p => {
    const displayType = p['amnezia-wg-option'] ? `awg ${p.awgVersion || ''}`.trim() : p.type;
    p.name = `${prefix} ${targetArray.length + 1} (${displayType})`;
    targetArray.push(p);
  });
  
  inputEl.value = '';
  showToast(`Добавлено серверов: ${newProxies.length}`, 'success');
  window.renderTable(type);
};

window.clearServers = function(type) {
  if (type === 'ru') window.ruProxies = [];
  if (type === 'foreign') window.foreignProxies = [];
  window.renderTable(type);
};

window.removeServer = function(type, index) {
  if (type === 'ru') window.ruProxies.splice(index, 1);
  if (type === 'foreign') window.foreignProxies.splice(index, 1);
  window.renderTable(type);
};

window.updateServerName = function(type, index, newName) {
  const arr = type === 'ru' ? window.ruProxies : window.foreignProxies;
  if (arr[index]) {
    arr[index].name = newName;
  }
};

window.renderTable = function(type) {
  const arr = type === 'ru' ? window.ruProxies : window.foreignProxies;
  const tbody = document.getElementById(`${type}-proxy-tbody`);
  const countSpan = document.getElementById(`${type}-proxy-count`);
  const card = document.getElementById(`${type}-proxy-card`);
  
  countSpan.textContent = arr.length;
  
  if (arr.length === 0) {
    card.style.display = 'none';
    tbody.innerHTML = '';
    return;
  }
  
  card.style.display = 'block';
  tbody.innerHTML = '';
  
  arr.forEach((p, index) => {
    const tr = document.createElement('tr');
    
    // Имя
    const tdName = document.createElement('td');
    const inputName = document.createElement('input');
    inputName.type = 'text';
    inputName.className = 'field-input';
    inputName.style.padding = '4px 8px';
    inputName.value = p.name || '';
    inputName.oninput = (e) => window.updateServerName(type, index, e.target.value);
    tdName.appendChild(inputName);
    tr.appendChild(tdName);
    
    // Тип
    const tdType = document.createElement('td');
    let displayType = p.type || 'unknown';
    if (p.type === 'wireguard' && p['amnezia-wg-option']) {
      displayType = `awg ${p.awgVersion || ''}`.trim();
    }
    tdType.textContent = displayType;
    tr.appendChild(tdType);
    
    // Сервер
    const tdServer = document.createElement('td');
    tdServer.textContent = p.server || p.ip || '';
    tr.appendChild(tdServer);
    
    // Порт
    const tdPort = document.createElement('td');
    tdPort.textContent = p.port || '';
    tr.appendChild(tdPort);
    
    // Действия (Удалить)
    const tdActions = document.createElement('td');
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn-sm btn-danger';
    btnDel.textContent = '✕';
    btnDel.onclick = () => window.removeServer(type, index);
    tdActions.appendChild(btnDel);
    tr.appendChild(tdActions);
    
    tbody.appendChild(tr);
  });
};

window.copyGeneratedConfig = function() {
  const code = document.getElementById('config-preview').textContent;
  if (!code) return;
  navigator.clipboard.writeText(code).then(() => {
    showToast('Конфиг скопирован в буфер обмена', 'success');
  }).catch(() => {
    showToast('Ошибка при копировании', 'error');
  });
};

window.downloadGeneratedConfig = function() {
  const code = document.getElementById('config-preview').textContent;
  if (!code) return;
  const blob = new Blob([code], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'config-ios.yaml';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

function showToast(message, type = 'info') {
  const toasts = document.getElementById('toasts');
  if (!toasts) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toasts.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

window.generateConfigUI = async function() {
  const ruText = document.getElementById('ru-servers-input').value.trim();
  const foreignText = document.getElementById('foreign-servers-input').value.trim();
  
  if (ruText || foreignText) {
    if (typeof showToast !== 'undefined') {
      showToast('У вас остались не добавленные серверы в текстовых полях. Нажмите "Добавить серверы", чтобы продолжить.', 'error');
    } else {
      alert('У вас остались не добавленные серверы в текстовых полях. Нажмите "Добавить серверы", чтобы продолжить.');
    }
    return;
  }
  
  const ruProxies = window.ruProxies || [];
  const foreignProxies = window.foreignProxies || [];
  
  if (ruProxies.length === 0 && foreignProxies.length === 0) {
    if (typeof showToast !== 'undefined') {
      showToast('Добавьте хотя бы один сервер, чтобы сгенерировать конфиг!', 'error');
    }
    return;
  }
  
  const allProxies = [...ruProxies, ...foreignProxies];
  
  const config = {
    mode: 'rule',
    ipv6: false,
    'log-level': 'info',
    'allow-lan': false,
    'unified-delay': true,
    'tcp-concurrent': true
  };

  const tgEnabled = document.getElementById('tg-proxy-enabled').checked;
  if (tgEnabled) {
    const port = parseInt(document.getElementById('tg-port').value, 10) || 1080;
    const login = document.getElementById('tg-login').value || 'telegram';
    const password = document.getElementById('tg-password').value || 'telegram';
    
    config['socks-port'] = port;
    config['authentication'] = [`${login}:${password}`];
  }

  config['sniffer'] = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    sniff: {
      HTTP: {
        ports: [80, '8080-8880'],
        'override-destination': true
      },
      TLS: {
        ports: [443, 8443]
      }
    }
  };

  config['dns'] = {
    enable: true,
    listen: '127.0.0.1:6868',
    ipv6: false,
    'prefer-ipv4': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.0/15',
    'fake-ip-filter': [
      '*.lan',
      '*.local',
      '+.msftconnecttest.com'
    ],
    'default-nameserver': ['8.8.8.8', '1.1.1.1'],
    nameserver: [
      'https://8.8.8.8/dns-query',
      'https://cloudflare-dns.com/dns-query'
    ],
    'nameserver-policy': {
      'geosite:category-ru': ['77.88.8.8', '8.8.8.8']
    }
  };

  if (allProxies.length > 0) {
    config['proxies'] = allProxies;
  }

  const ruProxyNames = ruProxies.map(p => p.name);
  const foreignProxyNames = foreignProxies.map(p => p.name);
  
  // Добавляем общие селекторы серверов
  config['proxy-groups'] = [];
  
  if (foreignProxyNames.length > 0) {
    config['proxy-groups'].push({
      name: '🌍 Иностранные серверы',
      type: 'select',
      proxies: [...foreignProxyNames]
    });
  }
  
  if (ruProxyNames.length > 0) {
    config['proxy-groups'].push({
      name: '🇷🇺 Российские серверы',
      type: 'select',
      proxies: [...ruProxyNames]
    });
  }

  // Вспомогательная функция для генерации списка прокси для конкретной группы
  const getProxiesList = (primaryIsRu) => {
    const list = [];
    if (primaryIsRu) {
      if (ruProxyNames.length > 0) list.push('🇷🇺 Российские серверы');
      if (foreignProxyNames.length > 0) list.push('🌍 Иностранные серверы');
      list.push(...ruProxyNames);
      list.push(...foreignProxyNames);
    } else {
      if (foreignProxyNames.length > 0) list.push('🌍 Иностранные серверы');
      list.push(...foreignProxyNames);
    }
    list.push('DIRECT');
    // Убираем дубликаты на всякий случай
    return [...new Set(list)];
  };

  const groups = [
    { name: '💬 Discord', primaryIsRu: true },
    { name: '▶️ YouTube', primaryIsRu: true },
    { name: '📸 Instagram & Threads', primaryIsRu: false },
    { name: '👥 Facebook', primaryIsRu: false },
    { name: '➤ Telegram', primaryIsRu: false },
    { name: '🤖 AI (Нейронки)', primaryIsRu: false },
    { name: '🎵 TikTok', primaryIsRu: false },
    { name: '👾 Brawl Stars', primaryIsRu: false },
    { name: '🎮 Roblox', primaryIsRu: false },
    { name: '🚫 Заблокированные сайты (RU)', primaryIsRu: false },
    { name: '📋 My Rules', primaryIsRu: false },
    { name: '🌐 Остальной трафик (MATCH)', primaryIsRu: false }
  ];

  groups.forEach(g => {
    let list = getProxiesList(g.primaryIsRu);
    // Для MATCH сделаем DIRECT первым по умолчанию
    if (g.name === '🌐 Остальной трафик (MATCH)') {
      list = ['DIRECT', '🌍 Иностранные серверы', '🇷🇺 Российские серверы', ...foreignProxyNames, ...ruProxyNames];
      // Удаляем дубликаты
      list = [...new Set(list)];
    }
    
    config['proxy-groups'].push({
      name: g.name,
      type: 'select',
      proxies: list
    });
  });

  config['rule-providers'] = {
    'geosite-youtube': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/youtube.mrs',
      path: './rule-sets/youtube.mrs',
      interval: 86400
    },
    'geosite-discord': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/discord.mrs',
      path: './rule-sets/discord.mrs',
      interval: 86400
    },
    'discord_voiceips': {
      behavior: 'ipcidr',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/discord-voice-ip-list.mrs',
      path: './rule-sets/discord_voiceips.mrs',
      interval: 86400
    },
    'geosite-instagram': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/instagram.mrs',
      path: './rule-sets/instagram.mrs',
      interval: 86400
    },
    'geosite-facebook': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/facebook.mrs',
      path: './rule-sets/facebook.mrs',
      interval: 86400
    },
    'geosite-tiktok': {
      behavior: 'domain',
      type: 'http',
      format: 'yaml',
      url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/tiktok.yaml',
      path: './rule-sets/tiktok.yaml',
      interval: 86400
    },
    'geosite-supercell': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/supercell.mrs',
      path: './rule-sets/supercell.mrs',
      interval: 86400
    },
    'geosite-roblox': {
      behavior: 'domain',
      type: 'http',
      format: 'yaml',
      url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/roblox.yaml',
      path: './rule-sets/roblox.yaml',
      interval: 86400
    },
    'telegram-domains': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/telegram.mrs',
      path: './rule-sets/telegram-domains.mrs',
      interval: 86400
    },
    'telegram-ips': {
      behavior: 'ipcidr',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/telegram.mrs',
      path: './rule-sets/telegram-ips.mrs',
      interval: 86400
    },
    'geosite-openai': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/openai.mrs',
      path: './rule-sets/openai.mrs',
      interval: 86400
    },
    'google-gemini': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/google-gemini.mrs',
      path: './rule-sets/google-gemini.mrs',
      interval: 86400
    },
    'geosite-anthropic': {
      behavior: 'domain',
      type: 'http',
      format: 'mrs',
      url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/anthropic.mrs',
      path: './rule-sets/anthropic.mrs',
      interval: 86400
    },
    'my-rules': {
      type: 'http',
      behavior: 'classical',
      format: 'yaml',
      url: 'https://raw.githubusercontent.com/chm0d777/mihomo-config/main/my-rules.yaml',
      path: './rule-sets/my-rules.yaml',
      interval: 86400
    },
    'ru-blocked': {
      behavior: 'classical',
      type: 'http',
      format: 'yaml',
      url: 'https://cdn.jsdelivr.net/gh/shvchk/unblock-net/lists/clash/ru-blocked',
      path: './rule-sets/ru-blocked.yaml',
      interval: 86400
    }
  };

  config['rules'] = [];

  if (tgEnabled) {
    const port = parseInt(document.getElementById('tg-port').value, 10) || 1080;
    config['rules'].push(`IN-PORT,${port},🌐 Остальной трафик (MATCH)`);
  }

  config['rules'].push(
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    
    'RULE-SET,geosite-youtube,▶️ YouTube',
    'OR,((RULE-SET,geosite-discord),(RULE-SET,discord_voiceips),(PROCESS-NAME,Discord.exe)),💬 Discord',
    
    'RULE-SET,geosite-instagram,📸 Instagram & Threads',
    'RULE-SET,geosite-facebook,👥 Facebook',
    'OR,((RULE-SET,telegram-ips),(RULE-SET,telegram-domains),(IP-ASN,59930),(DOMAIN,firebaselogging.googleapis.com),(DOMAIN,dns.google.com),(PROCESS-NAME,org.telegram.messenger),(PROCESS-NAME,org.telegram.messenger.web),(PROCESS-NAME,org.telegram.plus),(PROCESS-NAME,org.thunderdog.challegram),(PROCESS-NAME,Telegram.exe),(PROCESS-NAME,Telegram)),➤ Telegram',
    'RULE-SET,geosite-tiktok,🎵 TikTok',
    
    'OR,((RULE-SET,geosite-openai),(RULE-SET,google-gemini),(RULE-SET,geosite-anthropic),(DOMAIN-KEYWORD,grok),(DOMAIN-SUFFIX,grok.com),(DOMAIN-SUFFIX,appcenter.ms),(DOMAIN-KEYWORD,copilot),(DOMAIN-SUFFIX,copilot.microsoft.com)),🤖 AI (Нейронки)',
    
    'RULE-SET,geosite-supercell,👾 Brawl Stars',
    'RULE-SET,geosite-roblox,🎮 Roblox',
    
    'RULE-SET,ru-blocked,🚫 Заблокированные сайты (RU)',
    
    'RULE-SET,my-rules,📋 My Rules',
    
    'GEOIP,RU,DIRECT',
    'DOMAIN-SUFFIX,ru,DIRECT',
    'DOMAIN-SUFFIX,рф,DIRECT',
    'DOMAIN-SUFFIX,su,DIRECT',
    'MATCH,🌐 Остальной трафик (MATCH)'
  );

  const yamlStr = jsyaml.dump(config, {
    indent: 2,
    lineWidth: -1,
    noRefs: true,
    sortKeys: false
  });

  document.getElementById('config-preview').textContent = yamlStr;
  document.getElementById('result-card').style.display = 'block';
  
  if (typeof showToast !== 'undefined') {
    showToast('Конфигурация успешно сгенерирована!', 'success');
  }
  
  // Прокручиваем к результату
  document.getElementById('result-card').scrollIntoView({ behavior: 'smooth' });
};

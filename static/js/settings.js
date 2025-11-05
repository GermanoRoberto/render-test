document.addEventListener('DOMContentLoaded', function() {
  // Elementos da interface
  const vtKey = document.getElementById('vt-key');
  const triageKey = document.getElementById('triage-key');
  const saveKeys = document.getElementById('save-keys');
  const saveSettings = document.getElementById('save-settings');
  const validateVT = document.getElementById('validate-vt');
  const validateTriage = document.getElementById('validate-triage');
  const vtStatus = document.getElementById('vt-status');
  const triageStatus = document.getElementById('triage-status');

  // Carregar configurações salvas
  function loadSavedSettings() {
    try {
      const settings = JSON.parse(localStorage.getItem('malware_analyzer_settings') || '{}');
      if (settings.vtKey) {
        vtKey.value = settings.vtKey;
      }
      if (settings.triageKey) {
        triageKey.value = settings.triageKey;
      }
      saveKeys.checked = settings.saveKeys || false;
    } catch (e) {
      console.error('Erro ao carregar configurações:', e);
    }
  }

  // Validar chave do VirusTotal
  async function validateVirusTotalKey(key) {
    try {
      const res = await fetch('/api/validate_keys', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ apikey: key })
      });
      const data = await res.json();
      return data.ok;
    } catch (e) {
      console.error('Erro na validação:', e);
      return false;
    }
  }

  // Validar chave do Tria.ge
  async function validateTriageKey(key) {
    try {
      const res = await fetch('/api/validate_keys', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ apikey: key, service: 'triage' })
      });
      const data = await res.json();
      return data.ok;
    } catch (e) {
      console.error('Erro na validação:', e);
      return false;
    }
  }

  // Event listeners para validação
  validateVT.addEventListener('click', async () => {
    const key = vtKey.value.trim();
    if (!key) {
      vtStatus.textContent = 'Insira uma chave primeiro';
      vtStatus.className = 'key-status error';
      return;
    }

    vtStatus.textContent = 'Validando...';
    vtStatus.className = 'key-status';
    
    const isValid = await validateVirusTotalKey(key);
    if (isValid) {
      vtStatus.textContent = 'Chave válida!';
      vtStatus.className = 'key-status success';
    } else {
      vtStatus.textContent = 'Chave inválida';
      vtStatus.className = 'key-status error';
    }
  });

  validateTriage.addEventListener('click', async () => {
    const key = triageKey.value.trim();
    if (!key) {
      triageStatus.textContent = 'Insira uma chave primeiro';
      triageStatus.className = 'key-status error';
      return;
    }

    triageStatus.textContent = 'Validando...';
    triageStatus.className = 'key-status';
    
    const isValid = await validateTriageKey(key);
    if (isValid) {
      triageStatus.textContent = 'Chave válida!';
      triageStatus.className = 'key-status success';
    } else {
      triageStatus.textContent = 'Chave inválida';
      triageStatus.className = 'key-status error';
    }
  });

  // Salvar configurações
  saveSettings.addEventListener('click', async () => {
    const settings = {
      saveKeys: saveKeys.checked,
      vtKey: vtKey.value.trim(),
      triageKey: triageKey.value.trim()
    };

    if (settings.saveKeys) {
      try {
        localStorage.setItem('malware_analyzer_settings', JSON.stringify(settings));
        alert('Configurações salvas com sucesso!');
      } catch (e) {
        console.error('Erro ao salvar:', e);
        alert('Erro ao salvar configurações');
      }
    } else {
      localStorage.removeItem('malware_analyzer_settings');
      alert('Configurações limpas');
    }
  });

  // Carregar configurações ao iniciar
  loadSavedSettings();
});
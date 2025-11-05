document.addEventListener('DOMContentLoaded', function(){
  const fileInput = document.getElementById('file-input');
  const fileName = document.getElementById('file-name');
  const analyze = document.getElementById('analyze');
  const urlInput = document.getElementById('url-input');
  const tabFile = document.getElementById('tab-file');
  const tabUrl = document.getElementById('tab-url');
  const fileSection = document.getElementById('file-input-section');
  const urlSection = document.getElementById('url-input-section');
  const status = document.getElementById('result-status');
  const analysisTimeWarning = document.getElementById('analysis-time-warning');

  function setStatus(text){ 
    if(status) status.textContent = text; 
  }

  fileInput.addEventListener('change', () => {
    if(fileInput.files.length) fileName.textContent = fileInput.files[0].name;
    else fileName.textContent = 'Nenhum arquivo escolhido';
  });

  // Botão de colar URL
  const urlPasteBtn = document.getElementById('url-paste');
  if (urlPasteBtn) {
    urlPasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          urlInput.value = text;
        }
      } catch (err) {
        console.error('Erro ao acessar a área de transferência:', err);
        alert('Não foi possível acessar a área de transferência. Por favor, cole o link manualmente.');
      }
    });
  }

  // Manipulação das tabs
  tabFile.addEventListener('click', () => {
    tabFile.classList.add('active');
    tabUrl.classList.remove('active');
    fileSection.style.display = 'block';
    urlSection.style.display = 'none';
    analysisTimeWarning.style.display = 'none'; // Hide warning when switching tabs
  });

  tabUrl.addEventListener('click', () => {
    tabUrl.classList.add('active');
    tabFile.classList.remove('active');
    urlSection.style.display = 'block';
    fileSection.style.display = 'none';
    analysisTimeWarning.style.display = 'none'; // Hide warning when switching tabs
  });

  analyze.addEventListener('click', async () => {
    setStatus('Preparando...');
    // limpar elementos detalhados
    setStatus(''); // Limpa o status anterior
    analysisTimeWarning.style.display = 'block'; // Show warning when analysis starts
    // Verificar se estamos no modo URL ou arquivo
    const isUrlMode = urlSection.style.display !== 'none';
    
    if (isUrlMode) {
      const url = urlInput.value.trim();
      if (!url) {
        alert('Digite uma URL para analisar.');
        analysisTimeWarning.style.display = 'none'; // Hide warning if validation fails
        return;
      }
      
      let statusMessage = 'Analisando URL...';
      setStatus(statusMessage);

      const data = { url: url };

      try {
        analyze.disabled = true;
        analyze.textContent = 'Analisando...';
        const res = await fetch('/api/scan_url', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(data)
        });

        if (!res.ok) {
          const txt = await res.text();
          alert('Erro: ' + res.statusText);
          console.error(txt);
          return;
        }

        const jsonRes = await res.json();
        if (jsonRes.ok && jsonRes.redirect) {
          window.location.href = jsonRes.redirect;
        } else {
          alert('Análise retornou erro');
        }
      } catch (err) {
        console.error(err);
        alert('Erro na requisição');
      } finally {
        analyze.disabled = false;
        setStatus('');
        analyze.textContent = 'Iniciar Análise';
        analysisTimeWarning.style.display = 'none'; // Hide warning after analysis completes
      }
      return;
    }

    // Modo arquivo
    const fd = new FormData();
    if(fileInput.files.length){ fd.append('file', fileInput.files[0]); }
    else { 
      alert('Nenhum arquivo selecionado.'); 
      analysisTimeWarning.style.display = 'none'; // Hide warning if validation fails
      return; 
    }
    
    let statusMessage = 'Enviando e analisando arquivo...';
    setStatus(statusMessage);

    try{
      analyze.disabled = true; analyze.textContent = 'Analisando...';
      const res = await fetch('/api/scan', { method: 'POST', body: fd });
      if(!res.ok){ const txt = await res.text(); alert('Erro: '+res.statusText); console.error(txt); setStatus('Erro no servidor.'); return; }
      setStatus('Análise concluída. Redirecionando...');
      const data = await res.json();
              if (data.ok && data.redirect){
                window.location.href = data.redirect;
              } else {
                alert('Análise retornou erro');
                setStatus('Falha na análise.');
              }
    }catch(err){
      console.error(err);
      alert('Erro na requisição');
      setStatus('Erro de conexão.');
    }finally{
      analyze.disabled = false; analyze.textContent = 'Iniciar Análise';
      analysisTimeWarning.style.display = 'none'; // Hide warning after analysis completes
    }
  });

  // Manipulação dos formulários de atualização de chave
  const updateForms = document.querySelectorAll('.update-key-form');
  updateForms.forEach(form => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const keyName = form.dataset.keyName;
      const input = form.querySelector('input');
      const button = form.querySelector('button');
      const keyValue = input.value.trim();

      if (!keyValue) {
        alert('Por favor, insira a chave de API.');
        return;
      }

      button.disabled = true;
      button.textContent = 'Salvando...';

      try {
        const res = await fetch('/api/update_key', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ key_name: keyName, key_value: keyValue })
        });

        if (res.ok) {
          alert('Chave salva com sucesso! A página será recarregada para aplicar a alteração.');
          window.location.reload();
        } else {
          const errData = await res.json();
          alert(`Erro ao salvar a chave: ${errData.error}`);
        }
      } catch (err) {
        console.error('Erro na requisição de atualização:', err);
        alert('Não foi possível conectar ao servidor para atualizar a chave.');
      } finally {
        button.disabled = false;
        button.textContent = 'Salvar';
      }
    });
  });
});

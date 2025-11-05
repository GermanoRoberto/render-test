// Garante que o script só rode após o carregamento completo da página.
document.addEventListener('DOMContentLoaded', () => {

    // --- 1. Seleção de Elementos da UI ---
    const fileForm = document.getElementById('file-analysis-form');
    const urlForm = document.getElementById('url-analysis-form');
    const fileInput = document.getElementById('file-input');
    const urlInput = document.getElementById('url-input');
    const fileInputWrapper = document.querySelector('.file-input-wrapper');
    const fileNameDisplay = document.getElementById('file-name');
    const fileSubmitBtn = document.getElementById('file-submit-btn');
    const urlSubmitBtn = document.getElementById('url-submit-btn');
    const loaderOverlay = document.getElementById('loader-overlay');

    // Elementos das Abas
    const tabFile = document.getElementById('tab-file');
    const tabUrl = document.getElementById('tab-url');
    const fileSection = document.getElementById('file-section');
    const urlSection = document.getElementById('url-section');
    const tabAbout = document.getElementById('tab-about');
    const aboutSection = document.getElementById('about-section');

    // Função para habilitar/desabilitar o botão de análise.
    function updateButtonState() {
        fileSubmitBtn.disabled = fileInput.files.length === 0;
        urlSubmitBtn.disabled = urlInput.value.trim() === '';
    }

    // Função para mostrar o nome do arquivo selecionado.
    function displayFileName() {
        if (fileInput.files.length > 0) {
            fileNameDisplay.textContent = fileInput.files[0].name;
        } else {
            fileNameDisplay.textContent = '';
        }
        updateButtonState();
    }

    // --- 2. Lógica das Abas ---
    tabFile.addEventListener('click', () => {
        tabFile.classList.add('active');
        tabUrl.classList.remove('active');
        tabAbout.classList.remove('active');
        fileSection.style.display = 'block';
        urlSection.style.display = 'none';
        aboutSection.style.display = 'none';
    });

    tabUrl.addEventListener('click', () => {
        tabUrl.classList.add('active');
        tabFile.classList.remove('active');
        tabAbout.classList.remove('active');
        urlSection.style.display = 'block';
        fileSection.style.display = 'none';
        aboutSection.style.display = 'none';
    });

    tabAbout.addEventListener('click', () => {
        tabAbout.classList.add('active');
        tabFile.classList.remove('active');
        tabUrl.classList.remove('active');
        aboutSection.style.display = 'block';
        fileSection.style.display = 'none';
        urlSection.style.display = 'none';
    });

    // Quando o usuário digita no campo de URL.
    urlInput.addEventListener('input', updateButtonState);

    // Quando um arquivo é selecionado pelo clique.
    fileInput.addEventListener('change', displayFileName);

    // Eventos para a funcionalidade de "arrastar e soltar" (drag and drop).
    fileInputWrapper.addEventListener('dragover', (e) => {
        e.preventDefault(); // Previne o comportamento padrão do navegador.
        fileInputWrapper.classList.add('dragging');
    });

    fileInputWrapper.addEventListener('dragleave', () => {
        fileInputWrapper.classList.remove('dragging');
    });

    fileInputWrapper.addEventListener('drop', (e) => {
        e.preventDefault(); // Previne o comportamento padrão do navegador.
        fileInputWrapper.classList.remove('dragging');
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files; // Atribui os arquivos arrastados ao input.
            displayFileName(); // Chama a função para mostrar o nome e habilitar o botão.
        }
    });

    // --- 3. Lógica de Envio (Análise de Arquivo) ---
    fileForm.addEventListener('submit', async (e) => {
        e.preventDefault(); // Previne o recarregamento da página.

        if (fileInput.files.length === 0) {
            alert('Por favor, selecione um arquivo para analisar.');
            return;
        }

        loaderOverlay.style.display = 'flex'; // Mostra a tela de "carregando".

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        try {
            // Envia o arquivo para a API do nosso backend.
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData,
            });

            const result = await response.json();

            if (result.ok && result.result) {
                // Em vez de redirecionar, renderiza os resultados na página
                renderResults(result.result);
            } else {
                throw new Error(result.error || 'Ocorreu um erro desconhecido.');
            }
        } catch (error) {
            alert('Erro na análise: ' + error.message);
        } finally {
            loaderOverlay.style.display = 'none'; // Esconde a tela de "carregando" em caso de erro.
        }
    });

    // --- 4. Lógica de Envio (Análise de URL) ---
    urlForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            alert('Por favor, insira uma URL para analisar.');
            return;
        }

        loaderOverlay.style.display = 'flex';

        try {
            const response = await fetch('/api/scan_url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url }),
            });

            const result = await response.json();

            if (result.ok && result.result) {
                renderResults(result.result);
            } else {
                throw new Error(result.error || 'Ocorreu um erro desconhecido.');
            }
        } catch (error) {
            alert('Erro na análise: ' + error.message);
        } finally {
            loaderOverlay.style.display = 'none';
        }
    });

    // Inicia os botões no estado correto.
    updateButtonState();

    // Função para renderizar os resultados dinamicamente
    function renderResults(data) {
        const resultsContainer = document.getElementById('results-container');
        // Esconde todas as seções de formulário/sobre
        [fileSection, urlSection, aboutSection].forEach(sec => sec.style.display = 'none');

        const verdictClass = {
            'malicious': 'danger',
            'suspicious': 'warning',
            'clean': 'success',
            'unknown': 'muted',
            'not_found': 'muted' // Adiciona o novo status para estilização
        }[data.final_verdict] || 'muted';

        const vtStats = data.external.virustotal?.stats;
        const vtDetections = vtStats ? `${vtStats.malicious} / ${Object.values(vtStats).reduce((a, b) => a + b, 0)}` : 'N/A';

        // Prepara o HTML da análise de IA, preservando quebras de linha e adicionando emojis
        let aiHTML = '';
        if (data.ai_analysis && data.ai_analysis.explanation) {
            let formattedExplanation = data.ai_analysis.explanation
                .replace(/#+\s/g, '') // Remove os caracteres de título do Markdown (ex: "### Título" -> "Título")
                .replace(/\n/g, '<br>') // Converte quebras de linha para <br>
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // **texto** -> <strong>texto</strong>
                .replace(/Baixo 🟢/g, 'Baixo <span style="color: var(--success);">🟢</span>')
                .replace(/Médio 🟡/g, 'Médio <span style="color: var(--warning);">🟡</span>')
                .replace(/Alto 🔴/g, 'Alto <span style="color: var(--danger);">🔴</span>')
                .replace(/Crítico ⚫/g, 'Crítico <span style="color: var(--danger);">⚫</span>');

            aiHTML = `<hr style="border-color: var(--border); margin: 1.5rem 0;">
                      <div class="report-header">
                          <h3>Relatório da IA</h3>
                          <button id="copy-report-btn" class="copy-btn">
                              <svg height="14" viewBox="0 0 16 16" version="1.1" width="14" fill="currentColor"><path d="M0 4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2Zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1Zm3 1.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5Zm0 3a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5Zm0 3a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5Z"></path></svg>
                              Copiar
                          </button>
                      </div>
                      <div class="ai-report">${formattedExplanation}</div>`;
        }

        // Define o texto do veredito com base no status
        let verdictText = data.final_verdict.toUpperCase();
        if (data.final_verdict === 'not_found') {
            verdictText = 'NÃO LOCALIZADO NO BANCO DE DADOS';
        }

        // Cria o HTML dos resultados
        const resultsHTML = `
            <div class="card-body">
                <h2 style="margin-bottom: 1rem;">Resultado da Análise</h2>
                <p><strong>Item Analisado:</strong> ${data.file_name || data.url}</p>
                <p><strong>Veredito Final:</strong> <span style="color: var(--${verdictClass}); font-weight: bold; text-transform: uppercase;">${verdictText}</span></p>
                <hr style="border-color: var(--border); margin: 1rem 0;">
                <p><strong>VirusTotal:</strong> ${vtDetections} detecções</p>
                ${aiHTML}
                <button onclick="window.location.reload()" class="btn" style="margin-top: 1.5rem;">Analisar Outro Arquivo</button>
            </div>
        `;

        resultsContainer.innerHTML = resultsHTML;

        // Adiciona a lógica de clique ao botão de copiar, se ele existir
        const copyBtn = document.getElementById('copy-report-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                const reportText = data.ai_analysis.explanation;
                navigator.clipboard.writeText(reportText).then(() => {
                    // Feedback visual de que o texto foi copiado
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = 'Copiado!';
                    copyBtn.style.color = 'var(--success)';
                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.style.color = '';
                    }, 2000);
                }).catch(err => console.error('Erro ao copiar texto: ', err));
            });
        }
    }
});
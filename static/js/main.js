// Garante que o script só rode após o carregamento completo da página.
document.addEventListener('DOMContentLoaded', () => {

    // 1. Seleciona todos os elementos da interface com os quais vamos interagir.
    const form = document.getElementById('analysis-form');
    const fileInput = document.getElementById('file-input');
    const fileInputWrapper = document.querySelector('.file-input-wrapper');
    const fileNameDisplay = document.getElementById('file-name');
    const submitBtn = document.getElementById('submit-btn');
    const loaderOverlay = document.getElementById('loader-overlay');

    // Função para habilitar/desabilitar o botão de análise.
    function updateButtonState() {
        submitBtn.disabled = fileInput.files.length === 0;
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

    // 2. Adiciona os "ouvintes" de eventos aos elementos.

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

    // 3. Lógica principal: o que acontece ao enviar o formulário.
    form.addEventListener('submit', async (e) => {
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

            if (result.ok && result.redirect) {
                window.location.href = result.redirect; // Redireciona para a página de resultados.
            } else {
                throw new Error(result.error || 'Ocorreu um erro desconhecido.');
            }
        } catch (error) {
            alert('Erro na análise: ' + error.message);
            loaderOverlay.style.display = 'none'; // Esconde a tela de "carregando" em caso de erro.
        }
    });
});
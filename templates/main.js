document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analysis-form');
    const fileInput = document.getElementById('file-input');
    const fileInputWrapper = document.querySelector('.file-input-wrapper');
    const fileNameDisplay = document.getElementById('file-name');
    const submitBtn = document.getElementById('submit-btn');
    const loaderOverlay = document.getElementById('loader-overlay');

    // Função para atualizar o estado do botão
    function updateButtonState() {
        if (fileInput.files.length > 0) {
            submitBtn.disabled = false;
        } else {
            submitBtn.disabled = true;
        }
    }

    // Lidar com a seleção de arquivo
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            fileNameDisplay.textContent = fileInput.files[0].name;
        } else {
            fileNameDisplay.textContent = '';
        }
        updateButtonState();
    });

    // Lidar com Drag and Drop
    fileInputWrapper.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileInputWrapper.classList.add('dragging');
    });

    fileInputWrapper.addEventListener('dragleave', () => {
        fileInputWrapper.classList.remove('dragging');
    });

    fileInputWrapper.addEventListener('drop', (e) => {
        e.preventDefault();
        fileInputWrapper.classList.remove('dragging');
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            // Dispara o evento 'change' manualmente
            fileInput.dispatchEvent(new Event('change'));
        }
    });

    // Lidar com o envio do formulário
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (fileInput.files.length === 0) {
            alert('Por favor, selecione um arquivo para analisar.');
            return;
        }

        loaderOverlay.style.display = 'flex'; // Mostra o loader

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData,
            });

            const result = await response.json();

            if (result.ok && result.redirect) {
                window.location.href = result.redirect; // Redireciona para a página de resultados
            } else {
                alert('Erro na análise: ' + (result.error || 'Ocorreu um erro desconhecido.'));
                loaderOverlay.style.display = 'none'; // Esconde o loader em caso de erro
            }
        } catch (error) {
            alert('Erro de conexão: ' + error.message);
            loaderOverlay.style.display = 'none'; // Esconde o loader em caso de erro
        }
    });
});
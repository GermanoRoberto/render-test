// --- 1. Importações ---
const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');

// --- 2. Carregamento de Variáveis de Ambiente ---
dotenv.config();

// --- 3. Constantes e Configurações Globais ---
const VERSION = '1.0.0-node';
const PORT = process.env.PORT || 3000;

// Chaves de API
const {
    VT_API_KEY,
    AI_API_KEY
} = process.env;

// Configuração do Multer para upload de arquivos em memória
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 32 * 1024 * 1024 } });

// --- 4. Inicialização do Express ---
const app = express();

// --- 5. Middlewares ---
app.use(express.json()); // Para parsing de JSON no corpo das requisições
app.use(express.urlencoded({ extended: true })); // Para parsing de formulários
app.use(express.static(path.join(__dirname, 'static'))); // Servir arquivos estáticos
app.set('view engine', 'html'); // Configurar para usar arquivos .html
app.engine('html', require('ejs').renderFile); // Usar EJS para renderizar HTML (permite passar variáveis)
app.set('views', path.join(__dirname, 'templates')); // Definir a pasta de templates

// --- 6. Funções Auxiliares ---
const getKeyStatus = () => ({
    VT_API_KEY: !!VT_API_KEY,
    AI_API_KEY: !!AI_API_KEY
});

// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms)); // Não é mais necessário

// --- 7. Funções de Análise (traduzidas de Python) ---

// Função para consultar VirusTotal (exemplo simplificado)
async function queryVirustotal(sha256) {
    if (!VT_API_KEY) return { found: false, error: "VT_API_KEY não configurada." };
    const url = `https://www.virustotal.com/api/v3/files/${sha256}`;
    const headers = { 'x-apikey': VT_API_KEY };
    try {
        const response = await axios.get(url, { headers });
        const attrs = response.data.data.attributes;
        const stats = attrs.last_analysis_stats || {};
        const verdict = (stats.malicious || 0) > 0 ? 'malicious' : 'clean';
        return { found: true, verdict, stats, raw: response.data };
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return { found: false };
        }
        console.error("Erro no VirusTotal:", error.message);
        return { error: `Erro no VirusTotal: ${error.message}` };
    }
}

// Função para consultar VirusTotal para URLs
async function queryVirustotalUrl(urlToScan) {
    if (!VT_API_KEY) return { found: false, error: "VT_API_KEY não configurada." };
    const urlId = Buffer.from(urlToScan).toString('base64').replace(/=/g, '');
    const url = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    const headers = { 'x-apikey': VT_API_KEY };
    try {
        const response = await axios.get(url, { headers });
        const attrs = response.data.data.attributes;
        const stats = attrs.last_analysis_stats || {};
        const verdict = (stats.malicious || 0) > 0 ? 'malicious' : 'clean';
        return { found: true, verdict, stats, raw: response.data };
    } catch (error) {
        if (error.response && error.response.status === 404) {
            // Se a URL não foi analisada, podemos submetê-la para análise, mas por simplicidade, retornamos 'not found'.
            return { found: false, verdict: 'unknown' };
        }
        console.error("Erro no VirusTotal (URL):", error.message);
        return { error: `Erro no VirusTotal (URL): ${error.message}` };
    }
}

function calculateFinalVerdict(localVerdict, externalResults) {
    // Com apenas o VirusTotal, o veredito dele é o final.
    const vtResult = externalResults.virustotal;
    if (vtResult && vtResult.found) {
        return vtResult.verdict;
    }
    return localVerdict; // Retorna o veredito local se o VT não encontrar nada.
}

function analyzeBuffer(content, filename) {
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    const tags = [];
    if (content.toString('hex', 0, 2) === '4d5a') tags.push('pe_executable'); // "MZ"
    if (content.toString('hex', 0, 4) === '7f454c46') tags.push('elf_executable'); // ".ELF"

    const verdict = tags.includes('pe_executable') || tags.includes('elf_executable') ? 'suspicious' : 'unknown';

    return {
        file_name: filename,
        sha256: sha256,
        size_bytes: content.length,
        verdict: verdict,
        tags: tags,
        scanned_at: Math.floor(Date.now() / 1000)
    };
}

// Função para consultar a IA (Gemini)
async function queryAI(verdict, filename, externalResults) {
    if (!AI_API_KEY) {
        return { explanation: "A análise por IA não está configurada (chave de API ausente)." };
    }

    // Construir um prompt detalhado para a IA
    const vtResult = externalResults.virustotal;
    let detailedInfo = `O arquivo analisado é "${filename}" com um veredito final de "${verdict}".`;
    if (vtResult && vtResult.found) {
        detailedInfo += ` No VirusTotal, ${vtResult.stats.malicious} de ${Object.values(vtResult.stats).reduce((a, b) => a + b, 0)} antivírus o detectaram.`;
    }

    const basePrompt = `Você é um profissional de cibersegurança. Analise as seguintes informações: ${detailedInfo}

    Forneça uma orientação profissional e detalhada em Markdown, seguindo a estrutura:
    1.  **Nível de Risco:** (Baixo 🟢, Médio 🟡, Alto 🔴, Crítico ⚫).
    2.  **Explicação do Risco:** Descreva o impacto potencial e o porquê do veredito.
    3.  **Recomendação:** Ação clara a ser tomada pelo usuário (ex: "Delete este arquivo imediatamente").
    4.  **Dicas de Prevenção:** 2 dicas para evitar ameaças futuras.

    **ATENÇÃO (Conteúdo Adulto):** Se a análise da URL indicar que se trata de um site de conteúdo adulto, além da análise de segurança, adicione uma seção especial chamada "Nota Adicional" e inclua a seguinte mensagem: "Se o acesso a este tipo de conteúdo está causando desconforto ou problemas em sua vida, saiba que existem recursos disponíveis. Considerar conversar com um profissional de saúde mental, como um psicólogo, pode ser um passo positivo."`;

    const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

    try {
        const response = await axios.post(OPENAI_API_URL, {
            model: "gpt-3.5-turbo", // Modelo padrão da OpenAI
            messages: [{
                role: "user",
                content: basePrompt
            }]
        }, {
            headers: { 'Authorization': `Bearer ${AI_API_KEY}` }
        });

        if (response.data.choices && response.data.choices.length > 0) {
            return { explanation: response.data.choices[0].message.content };
        } else {
            return { explanation: "A resposta da OpenAI retornou vazia." };
        }
    } catch (error) {
        console.error("Erro na API OpenAI:", error.response ? error.response.data : error.message);
        return { error: "Falha ao comunicar com a API de IA." };
    }
}

// --- 9. Definição das Rotas (Endpoints) ---

app.get('/', (req, res) => {
    // A página principal sempre será renderizada.
    // O template index.html mostrará quais chaves estão ativas.
    res.render('index', { key_status: getKeyStatus() });
});

app.get('/faq', (req, res) => {
    res.render('faq');
});

// Rota de API para análise de URL
app.post('/api/scan_url', async (req, res) => {
    if (!VT_API_KEY) {
        return res.status(403).json({ ok: false, error: "Aplicação não configurada." });
    }
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ ok: false, error: "URL não fornecida." });
    }

    console.log(`Recebida URL para análise: ${url}`);

    const vtResult = await queryVirustotalUrl(url);
    const externalResults = { virustotal: vtResult };
    const finalVerdict = calculateFinalVerdict('unknown', externalResults);

    const aiAnalysis = await queryAI(finalVerdict, url, externalResults);

    const result = {
        url: url, // Usamos 'url' em vez de 'file_name'
        external: externalResults,
        final_verdict: finalVerdict,
        ai_analysis: aiAnalysis,
        scanned_at: Math.floor(Date.now() / 1000)
    };

    res.json({ ok: true, result: result });
});

// Rota de API para análise de arquivo
app.post('/api/scan', upload.single('file'), async (req, res) => {
    if (!VT_API_KEY) { // Apenas a chave do VT é obrigatória para a análise
        return res.status(403).json({ ok: false, error: "Aplicação não configurada." });
    }
    if (!req.file) {
        return res.status(400).json({ ok: false, error: "Nenhum arquivo fornecido." });
    }

    const filename = req.file.originalname || 'uploaded_file';
    const content = req.file.buffer;

    console.log(`Recebido arquivo ${filename} (${content.length} bytes)`);

    const localResult = analyzeBuffer(content, filename);
    const sha256 = localResult.sha256;

    // Executar análises externas em paralelo
    const vtResult = await queryVirustotal(sha256);

    const externalResults = { virustotal: vtResult };
    const finalVerdict = calculateFinalVerdict(localResult.verdict, externalResults);

    // Chama a análise de IA
    const aiAnalysis = await queryAI(finalVerdict, filename, externalResults);

    const result = {
        ...localResult,
        external: externalResults,
        final_verdict: finalVerdict,
        ai_analysis: aiAnalysis
    };

    // Responde diretamente com o objeto de resultado em JSON
    res.json({ ok: true, result: result });
});

// Rota de Health Check
app.get('/api/health', (req, res) => {
    res.json({ ok: true, version: VERSION, runtime: 'node.js' });
});

// --- 10. Inicialização do Servidor ---
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    if (!VT_API_KEY) {
        console.warn("AVISO: A chave do VirusTotal (VT_API_KEY) não foi encontrada. A funcionalidade de análise estará desativada.");
    }
});
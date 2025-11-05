// --- 1. Importações ---
const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const session = require('express-session');
const FileStore = require('session-file-store')(session); // Importa o file store

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

// Configuração da Session
// O FileStore irá criar uma pasta 'sessions' para salvar os dados de forma persistente.
app.use(session({
    store: new FileStore({
        path: './sessions', // Caminho para a pasta de sessões
        ttl: 86400, // Tempo de vida da sessão em segundos (1 dia)
        retries: 0
    }),
    secret: crypto.randomBytes(24).toString('hex'), // Chave secreta para a session
    resave: false,
    saveUninitialized: false, // Não salva sessões vazias
    cookie: { secure: process.env.NODE_ENV === 'production' } // Usar cookies seguros em produção
}));

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

// --- 9. Definição das Rotas (Endpoints) ---

app.get('/', (req, res) => {
    // A página principal sempre será renderizada.
    // O template index.html mostrará quais chaves estão ativas.
    res.render('index', { key_status: getKeyStatus() });
});

app.get('/faq', (req, res) => {
    res.render('faq');
});

app.get('/results', (req, res) => {
    const result = req.session.last_result;
    if (!result) {
        return res.redirect('/');
    }
    // Limpa o resultado da sessão após exibi-lo
    req.session.last_result = null;
    res.render('results', { result });
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

    const result = {
        ...localResult,
        external: externalResults,
        final_verdict: finalVerdict,
        // A análise de IA pode ser adicionada aqui de forma similar
    };

    // Armazena o resultado na sessão do usuário
    req.session.last_result = result;

    res.json({ ok: true, redirect: '/results' });
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
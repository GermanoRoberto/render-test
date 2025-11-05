// --- 1. Importações ---
const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const session = require('express-session');

// --- 2. Carregamento de Variáveis de Ambiente ---
dotenv.config();

// --- 3. Constantes e Configurações Globais ---
const VERSION = '1.0.0-node';
const PORT = process.env.PORT || 3000;

// Chaves de API
const {
    VT_API_KEY,
    TRIAGE_API_KEY,
    AI_API_KEY,
    WHATSAPP_ACCESS_TOKEN,
    WHATSAPP_VERIFY_TOKEN,
    WHATSAPP_PHONE_NUMBER_ID
} = process.env;

// URLs e Modelos
const META_API_URL = `https://graph.facebook.com/v19.0/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

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
app.use(session({
    secret: crypto.randomBytes(24).toString('hex'), // Chave secreta para a session
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Usar cookies seguros em produção
}));

// --- 6. Funções Auxiliares ---
const isConfigured = () => !!(VT_API_KEY || TRIAGE_API_KEY);

const getKeyStatus = () => ({
    VT_API_KEY: !!VT_API_KEY,
    TRIAGE_API_KEY: !!TRIAGE_API_KEY,
    AI_API_KEY: !!AI_API_KEY,
    WHATSAPP_ACCESS_TOKEN: !!WHATSAPP_ACCESS_TOKEN,
    WHATSAPP_VERIFY_TOKEN: !!WHATSAPP_VERIFY_TOKEN,
    WHATSAPP_PHONE_NUMBER_ID: !!WHATSAPP_PHONE_NUMBER_ID,
});

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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

// Função para consultar Tria.ge (exemplo simplificado)
async function queryTriage(sha256) {
    if (!TRIAGE_API_KEY) return { found: false, error: "TRIAGE_API_KEY não configurada." };
    const url = `https://tria.ge/api/v0/search?query=${sha256}`;
    const headers = { 'Authorization': `Bearer ${TRIAGE_API_KEY}` };
    try {
        const response = await axios.get(url, { headers });
        if (response.data.data && response.data.data.length > 0) {
            const sample = response.data.data[0];
            // Em uma implementação real, você faria o polling no overview como no código Python
            const verdict = sample.verdict || 'unknown';
            return { found: true, verdict, raw: sample };
        }
        return { found: false };
    } catch (error) {
        console.error("Erro no Tria.ge:", error.message);
        return { error: `Erro no Tria.ge: ${error.message}` };
    }
}

function calculateFinalVerdict(localVerdict, externalResults) {
    if (Object.values(externalResults).some(res => res && res.verdict === 'malicious')) {
        return 'malicious';
    }
    if (Object.values(externalResults).some(res => res && res.verdict === 'suspicious')) {
        return 'suspicious';
    }
    if (Object.values(externalResults).some(res => res && res.verdict === 'clean')) {
        return 'clean';
    }
    return localVerdict;
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

// --- 8. Funções de Integração com WhatsApp ---

async function sendWhatsappMessage(to, text) {
    if (!WHATSAPP_ACCESS_TOKEN || !WHATSAPP_PHONE_NUMBER_ID) {
        console.error("WhatsApp não configurado. Faltam tokens.");
        return;
    }
    const payload = {
        messaging_product: "whatsapp",
        to: to,
        text: { body: text },
    };
    const headers = {
        "Authorization": `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
        "Content-Type": "application/json",
    };
    try {
        await axios.post(META_API_URL, payload, { headers });
        console.log(`Mensagem enviada para ${to}.`);
    } catch (error) {
        console.error(`Erro ao enviar mensagem para ${to}:`, error.response ? error.response.data : error.message);
    }
}

async function downloadWhatsappMedia(mediaId) {
    const headers = { "Authorization": `Bearer ${WHATSAPP_ACCESS_TOKEN}` };
    try {
        // 1. Obter a URL da mídia
        const urlInfoResponse = await axios.get(`https://graph.facebook.com/v19.0/${mediaId}`, { headers });
        const mediaUrl = urlInfoResponse.data.url;
        if (!mediaUrl) {
            return { error: "URL de mídia não encontrada na resposta da Meta." };
        }

        // 2. Baixar o conteúdo da mídia
        const mediaContentResponse = await axios.get(mediaUrl, { headers, responseType: 'arraybuffer' });
        return { content: mediaContentResponse.data };
    } catch (error) {
        console.error("Erro ao baixar mídia do WhatsApp:", error.message);
        return { error: `Erro ao baixar mídia: ${error.message}` };
    }
}

async function handleWhatsappAnalysis(messageData) {
    const fromNumber = messageData.from;
    const msgType = messageData.type;

    await sendWhatsappMessage(fromNumber, "Recebido! Iniciando análise, por favor aguarde...");

    if (msgType === 'document') {
        const mediaId = messageData.document.id;
        const filename = messageData.document.filename || 'arquivo_whatsapp';

        const { content, error } = await downloadWhatsappMedia(mediaId);
        if (error) {
            await sendWhatsappMessage(fromNumber, `Desculpe, não consegui baixar seu arquivo. Erro: ${error}`);
            return;
        }

        // --- Lógica de Análise de Arquivo ---
        const localResult = analyzeBuffer(content, filename);
        const sha256 = localResult.sha256;

        // Executar análises externas em paralelo
        const [vtResult, triageResult] = await Promise.all([
            queryVirustotal(sha256),
            queryTriage(sha256)
        ]);

        const externalResults = { virustotal: vtResult, triage: triageResult };
        const finalVerdict = calculateFinalVerdict(localResult.verdict, externalResults);

        // Formatar resposta
        const vtDetections = vtResult.stats?.malicious || 0;
        const triageVerdict = triageResult.verdict || 'N/A';

        const responseText = `--- Análise Concluída ---\n\n` +
            `Arquivo: ${filename}\n` +
            `Veredito Final: *${finalVerdict.toUpperCase()}*\n\n` +
            `Detalhes:\n` +
            `- VirusTotal: ${vtDetections} detecções\n` +
            `- Tria.ge: ${triageVerdict}\n\n` +
            `Recomendação: Com base no veredito '${finalVerdict}', recomendamos cautela.`;

        await sendWhatsappMessage(fromNumber, responseText);
    } else {
        await sendWhatsappMessage(fromNumber, "Olá! Por favor, envie um arquivo para análise. Análise de URLs e texto ainda não é suportada via WhatsApp.");
    }
}

// --- 9. Definição das Rotas (Endpoints) ---

app.get('/', (req, res) => {
    if (!isConfigured()) {
        // Em Node.js, não temos uma página de setup via UI. A configuração é só por .env.
        // Mostramos uma mensagem de erro ou a página principal com indicadores.
        res.send("<h1>Aplicação não configurada</h1><p>Por favor, configure as chaves de API nas variáveis de ambiente.</p>");
        return;
    }
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
    if (!isConfigured()) {
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
    const [vtResult, triageResult] = await Promise.all([
        queryVirustotal(sha256),
        queryTriage(sha256)
    ]);

    const externalResults = { virustotal: vtResult, triage: triageResult };
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

// Rota de API para o Webhook do WhatsApp
app.get('/api/whatsapp', (req, res) => {
    const verifyToken = req.query['hub.verify_token'];
    if (verifyToken === WHATSAPP_VERIFY_TOKEN) {
        console.log("Webhook do WhatsApp verificado com sucesso!");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.warn("Falha na verificação do Webhook. Token inválido.");
        res.status(403).send("Token de verificação inválido");
    }
});

app.post('/api/whatsapp', (req, res) => {
    const data = req.body;
    console.log("Webhook do WhatsApp recebido:", JSON.stringify(data, null, 2));

    if (data.object === 'whatsapp_business_account') {
        data.entry?.forEach(entry => {
            entry.changes?.forEach(change => {
                if (change.field === 'messages') {
                    const messageData = change.value.messages[0];
                    if (messageData) {
                        // Não bloqueia a resposta para a Meta. A análise roda em background.
                        handleWhatsappAnalysis(messageData).catch(err => {
                            console.error("Erro ao manusear análise do WhatsApp:", err);
                        });
                    }
                }
            });
        });
    }

    res.status(200).json({ status: "ok" });
});

// Rota de Health Check
app.get('/api/health', (req, res) => {
    res.json({ ok: true, version: VERSION, runtime: 'node.js' });
});

// --- 10. Inicialização do Servidor ---
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    if (!isConfigured()) {
        console.warn("AVISO: Nenhuma chave de API principal (VT ou Triage) foi encontrada. A funcionalidade será limitada.");
    }
});
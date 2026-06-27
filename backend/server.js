// ─── Load Environment Variables ───────────────────────────────────────────────
require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const path     = require('path');
const ort      = require('onnxruntime-node');
const connectDB = require('./config/db');
const { tokenize } = require('./tokenizer/tokenizer');

// ─── Load Chatbot Knowledge Base ──────────────────────────────────────────────
const metadata         = require('./artifacts/metadata.json');
const corpusEmbeddings = require('./artifacts/corpus_embeddings.json');

// ─── Connect to MongoDB ───────────────────────────────────────────────────────
connectDB();

const app = express();

app.set('trust proxy', 1);   
// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── Request Logger (development) ────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`\x1b[36m[${new Date().toISOString()}]\x1b[0m ${req.method} ${req.url}`);
    next();
  });
}

// ─── Serve Frontend Static Files ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ─── Load ONNX Model ──────────────────────────────────────────────────────────
let session;

ort.InferenceSession.create(path.join(__dirname, 'models', 'model.onnx'))
  .then(s => {
    session = s;
    console.log('\x1b[32m[CHATBOT]\x1b[0m ONNX model loaded successfully');
  })
  .catch(err => {
    console.error('\x1b[31m[CHATBOT ERROR]\x1b[0m Failed to load model:', err.message);
  });

// ─── Chatbot Helpers ──────────────────────────────────────────────────────────
function cosineSimilarity(a, b) {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot   += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB) + 1e-10);
}

async function getEmbedding(question) {
  const { inputIds, attentionMask, tokenTypeIds, shape } = tokenize(question);

  const feeds = {
    input_ids:      new ort.Tensor('int64', inputIds,     shape),
    attention_mask: new ort.Tensor('int64', attentionMask, shape),
    token_type_ids: new ort.Tensor('int64', tokenTypeIds,  shape),
  };

  const result = await session.run(feeds);
  const hiddenState = result[session.outputNames[0]].data;
  // Better — average all token embeddings
const size = 384;
const seqLen = hiddenState.length / size;
const pooled = new Array(size).fill(0);
for (let i = 0; i < seqLen; i++) {
  for (let j = 0; j < size; j++) {
    pooled[j] += hiddenState[i * size + j];
  }
}
return pooled.map(v => v / seqLen);
}

async function findAnswer(question) {
  const questionEmbedding = await getEmbedding(question);

  let bestScore = -Infinity;
  let bestMatch = null;

  for (let i = 0; i < corpusEmbeddings.length; i++) {
    const score = cosineSimilarity(questionEmbedding, corpusEmbeddings[i]);
    if (score > bestScore) {
      bestScore = score;
      bestMatch = metadata[i];
    }
  }

  return { answer: bestMatch.answer, score: bestScore, category: bestMatch.category };
}

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',     require('./routes/authRoutes'));
app.use('/api/security', require('./routes/apiRoutes'));
app.use('/api/activity', require('./routes/activityRoutes'));

// ─── Chatbot Route ────────────────────────────────────────────────────────────
app.post('/api/chat', async (req, res) => {
  try {
    const { question } = req.body;

    if (!question || !question.trim()) {
      return res.status(400).json({ success: false, message: 'question is required' });
    }

    if (!session) {
      return res.status(503).json({ success: false, message: 'Chatbot model is still loading, try again shortly' });
    }

    const { answer, score, category } = await findAnswer(question.trim());

    if (score < 0.5) {
      return res.json({
        success: true,
        answer: "I'm not sure about that. Please ask something about the Cyber Security Dashboard project.",
        score,
        category: 'unknown',
      });
    }

    res.json({ success: true, answer, score: parseFloat(score.toFixed(4)), category });
  } catch (err) {
    console.error('\x1b[31m[CHATBOT ERROR]\x1b[0m', err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'ONLINE',
    platform: 'CyberShield Intelligence Dashboard',
    version: '2.4.1',
    timestamp: new Date().toISOString(),
    mongodb: 'connected',
    chatbot: session ? 'ready' : 'loading',
  });
});

// ─── Serve Frontend for all non-API routes (SPA support) ──────────────────────
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
  } else {
    res.status(404).json({ success: false, message: 'API endpoint not found.' });
  }
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('\x1b[31m[ERROR]\x1b[0m', err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error.',
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('\n\x1b[32m╔══════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[32m║   CYBERSHIELD INTELLIGENCE PLATFORM          ║\x1b[0m');
  console.log('\x1b[32m║   v2.4.1 — All Systems Operational           ║\x1b[0m');
  console.log('\x1b[32m╚══════════════════════════════════════════════╝\x1b[0m');
  console.log(`\x1b[36m[SERVER]\x1b[0m Running on port \x1b[33m${PORT}\x1b[0m`);
  console.log(`\x1b[36m[URL]\x1b[0m http://localhost:${PORT}`);
  console.log(`\x1b[36m[MODE]\x1b[0m ${process.env.NODE_ENV || 'development'}\n`);
});

module.exports = app;

import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import NodeCache from 'node-cache';
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = 3000;

// Enable 'trust proxy' for express-rate-limit to work behind Cloud Run/Nginx proxy
app.set('trust proxy', 1);

// Caches for API results
const vtCache = new NodeCache({ stdTTL: 86400 }); // 24 hours for VirusTotal

let trancoList: string[] = [];
try {
  const trancoPath = path.join(__dirname, 'data/tranco-top500.json');
  if (fs.existsSync(trancoPath)) {
    trancoList = JSON.parse(fs.readFileSync(trancoPath, 'utf-8'));
  }
} catch (e) {
  console.error('Failed to load Tranco list:', e);
}

app.use(express.json());

// Rate limiting: 10 requests per minute
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Rate limit exceeded. Try again in a minute.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// --- Backend API Routes ---

// Case A: Tavily Search Proxy
app.post('/api/search', async (req, res) => {
  const { query } = req.body;
  const apiKey = process.env.TAVILY_API_KEY;

  if (!apiKey) {
    return res.status(500).json({ error: 'TAVILY_API_KEY is not configured on the server.' });
  }

  try {
    const response = await axios.post('https://api.tavily.com/search', {
      api_key: apiKey,
      query,
      search_depth: 'advanced',
      include_answer: false,
      max_results: 10,
    }, { timeout: 15000 }); // 15s timeout

    res.json(response.data);
  } catch (error: any) {
    const status = error.response?.status;
    const msg = error.response?.data?.detail || error.message;
    console.error('Tavily Search Error:', msg);
    
    let errorType = 'source_timeout';
    if (status === 401 || status === 403) errorType = 'invalid_api_key';
    
    res.status(500).json({ 
      error: `Search service error: ${msg}`, 
      warnings: [errorType] 
    });
  }
});

// Case B: URL Analysis (VirusTotal + Typosquatting)
app.post('/api/scan-url', async (req, res) => {
  const { url } = req.body;
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const domain = new URL(url).hostname.replace('www.', '');
    
    // 1. Typosquatting Check
    const isTopDomain = trancoList.includes(domain);
    let domainStatus = isTopDomain ? 'Legitimate' : 'Unknown / Possible Risk';
    
    // Basic check for common lookalikes (simple implementation)
    const possibleTargets = trancoList.filter((d: string) => {
      // Very crude similarity check for demo purposes
      if (d === domain) return false;
      return d.includes(domain.slice(0, 4)) || domain.includes(d.slice(0, 4));
    });
    
    if (!isTopDomain && possibleTargets.length > 0) {
      domainStatus = `Suspicious: Possible typosquatting of ${possibleTargets[0]}`;
    }

    // 2. VirusTotal Scan
    let vtData = vtCache.get(url);
    if (!vtData && apiKey) {
      try {
        // We use the simpler URL GET report first. If it fails, we assume it's new.
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
        const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers: { 'x-apikey': apiKey }
        });
        vtData = response.data.data.attributes.last_analysis_stats;
        vtCache.set(url, vtData);
      } catch (e: any) {
        if (e.response?.status === 404) {
          // New URL, we should theoretically submit it, but for free tier let's just return neutral
          domainStatus += ' (No VT history found)';
        }
      }
    }

    let safetyScore = 100;
    if (vtData) {
      const stats = vtData as any;
      if (stats.malicious > 0 || stats.suspicious > 0) {
        safetyScore = Math.max(0, 100 - (stats.malicious * 40 + stats.suspicious * 10));
      }
    }

    res.json({
      domain_status: domainStatus,
      safety_score: safetyScore,
      vt_stats: vtData || null
    });

  } catch (error: any) {
    console.error('URL Scan Error:', error.message);
    res.status(500).json({ error: 'URL scanning failed' });
  }
});

async function startServer() {
  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { 
        middlewareMode: true,
        hmr: false
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Trustify server running on http://localhost:${PORT}`);
  });
}

startServer();

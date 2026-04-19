/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { GoogleGenAI, Type } from "@google/genai";
import { 
  Search, 
  ShieldCheck, 
  AlertTriangle, 
  ExternalLink, 
  History, 
  Copy, 
  Check, 
  Loader2, 
  Globe, 
  FileText,
  Trash2,
  ChevronRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { InputType, VerificationResult, Source } from './types';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// System mission prompt
const SYSTEM_PROMPT = `[DRY ANALYSIS MISSION: OBJECTIVE_FACT_CHECK]
TASK: Verify the following claim using the provided search results.
OUTPUT: Strict JSON format matching VerificationResult interface.
RULES:
1. NO sentiment. NO polite fillers. Only raw findings.
2. Weighting: Official (Gov, Edu, Mainstream, Wiki) = 1.0. Social (Reddit, X) = 0.4.
3. If search results are empty or irrelevant, summary MUST be "No verifiable information found".
4. Score cannot exceed 60% if ONLY social media sources exist.
5. Output MUST be valid JSON.`;

const apiKey = process.env.GEMINI_API_KEY || '';
const ai = new GoogleGenAI({ apiKey });

export default function App() {
  const [input, setInput] = useState('');
  const [inputType, setInputType] = useState<InputType | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [history, setHistory] = useState<VerificationResult[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('trustify_history');
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  const saveToHistory = (res: VerificationResult) => {
    const newHistory = [res, ...history].slice(0, 5);
    setHistory(newHistory);
    localStorage.setItem('trustify_history', JSON.stringify(newHistory));
  };

  const detectInputType = (val: string): InputType => {
    const urlPattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
    return urlPattern.test(val) ? 'url' : 'text';
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setInput(val);
    if (val) {
      setInputType(detectInputType(val));
    } else {
      setInputType(null);
    }
  };

  const performVerification = async () => {
    if (!input) return;
    setLoading(true);
    setResult(null);

    const type = detectInputType(input);

    try {
      if (type === 'url') {
        const vtKey = process.env.VIRUSTOTAL_API_KEY;
        if (!vtKey) {
          setResult({
            input_type: 'url',
            score: null,
            summary: 'VirusTotal API key is missing. Add it in Settings > Secrets.',
            sources: [],
            warnings: ['config_error']
          });
          setLoading(false);
          return;
        }

        setLoadingStep('Scanning URL via VirusTotal & Tranco...');
        const res = await fetch('/api/scan-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: input }),
        });
        const data = await res.json();
        
        const scanResult: VerificationResult = {
          input_type: 'url',
          score: data.safety_score,
          summary: `Domain Legitimacy: ${data.domain_status}`,
          sources: [{ title: 'VirusTotal Scan', url: input, category: 'official' }],
          warnings: data.safety_score < 70 ? ['suspicious_reputation'] : [],
          safety_score: data.safety_score,
          domain_status: data.domain_status
        };
        setResult(scanResult);
        saveToHistory(scanResult);
      } else {
        const tavilyKey = process.env.TAVILY_API_KEY;
        if (!tavilyKey) {
          setResult({
            input_type: 'text',
            score: null,
            summary: 'Tavily API key is missing. Add it in Settings > Secrets.',
            sources: [],
            warnings: ['config_error']
          });
          setLoading(false);
          return;
        }

        setLoadingStep('Retrieving sources via Tavily...');
        const searchRes = await fetch('/api/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: input }),
        });
        const searchData = await searchRes.json();
        
        if (searchData.error) throw new Error(searchData.error);

        setLoadingStep('Cross-referencing via Gemini...');
        const prompt = `CLAIM: ${input}\n\nSEARCH_RESULTS: ${JSON.stringify(searchData.results)}`;
        
        const aiResponse = await ai.models.generateContent({
          model: 'gemini-3-flash-preview',
          contents: prompt,
          config: {
            systemInstruction: SYSTEM_PROMPT,
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                score: { type: Type.NUMBER, description: "Trust score from 0 to 100" },
                summary: { type: Type.STRING, description: "1-2 sentence dry summary" },
                sources: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      title: { type: Type.STRING },
                      url: { type: Type.STRING },
                      category: { type: Type.STRING, enum: ["official", "social"] }
                    },
                    required: ["title", "url", "category"]
                  }
                },
                warnings: {
                  type: Type.ARRAY,
                  items: { type: Type.STRING }
                }
              },
              required: ["score", "summary", "sources", "warnings"]
            }
          }
        });

        const verificationData = JSON.parse(aiResponse.text || '{}');
        const finalResult: VerificationResult = {
          ...verificationData,
          input_type: 'text'
        };
        setResult(finalResult);
        saveToHistory(finalResult);
      }
    } catch (err) {
      console.error(err);
      setResult({
        input_type: type,
        score: null,
        summary: 'Verification service unavailable',
        sources: [],
        warnings: ['source_timeout']
      });
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const copyResult = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getScoreColor = (score: number | null) => {
    if (score === null) return 'border-zinc-800';
    if (score >= 70) return 'border-emerald-500 text-emerald-500';
    if (score >= 40) return 'border-amber-500 text-amber-500';
    return 'border-rose-500 text-rose-500';
  };

  const getScoreBg = (score: number | null) => {
    if (score === null) return 'bg-zinc-900';
    if (score >= 70) return 'bg-emerald-500/10';
    if (score >= 40) return 'bg-amber-500/10';
    return 'bg-rose-500/10';
  };

  return (
    <div className="min-h-screen bg-[#050505] text-zinc-100 font-sans selection:bg-zinc-800">
      <header className="border-b border-zinc-800 p-6 flex justify-between items-center sticky top-0 bg-[#050505]/80 backdrop-blur-md z-40">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-zinc-100 flex items-center justify-center rounded-sm">
            <ShieldCheck className="text-[#050505] w-5 h-5" />
          </div>
          <h1 className="text-xl font-bold tracking-tighter uppercase italic">Trustify</h1>
          <span className="text-[10px] bg-zinc-800 px-1.5 py-0.5 rounded-sm font-mono text-zinc-400">v1.5.Pro</span>
        </div>
        <button 
          onClick={() => setShowHistory(!showHistory)}
          className="p-2 hover:bg-zinc-800 rounded-lg transition-colors"
        >
          <History className="w-5 h-5" />
        </button>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-12">
        <section className="space-y-8">
          <div className="space-y-2 text-center">
            <h2 className="text-4xl font-black uppercase tracking-tight sm:text-6xl">
              Objective <br/>Truth Engine
            </h2>
            <p className="text-zinc-500 font-mono text-sm">Strict data cross-referencing. No sentiment logic.</p>
          </div>

          <div className="relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-zinc-800 to-zinc-700 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
            <div className="relative bg-zinc-900 border border-zinc-800 rounded-xl p-2 flex items-center">
              <Search className="ml-4 text-zinc-500 w-5 h-5" />
              <input 
                type="text" 
                value={input}
                onChange={handleInputChange}
                placeholder="Enter claim or URL to verify..."
                className="flex-1 bg-transparent border-none focus:ring-0 px-4 py-4 text-lg outline-none"
                onKeyDown={(e) => e.key === 'Enter' && performVerification()}
              />
              {inputType && (
                <div className="hidden sm:flex items-center gap-2 px-3 py-1 bg-zinc-800 rounded-md mr-2">
                  {inputType === 'url' ? <Globe className="w-3 h-3" /> : <FileText className="w-3 h-3" />}
                  <span className="text-[10px] font-mono uppercase font-bold tracking-widest">{inputType}</span>
                </div>
              )}
              <button 
                disabled={loading || !input}
                onClick={performVerification}
                className="bg-zinc-100 text-black px-6 py-3 rounded-lg font-bold text-sm hover:bg-white disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'VERIFY'}
              </button>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {loading && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="flex flex-col items-center justify-center py-12 space-y-4"
              >
                <div className="relative w-16 h-16">
                  <motion.div 
                    animate={{ rotate: 360 }}
                    transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                    className="absolute inset-0 border-2 border-dashed border-zinc-700 rounded-full"
                  />
                  <div className="absolute inset-4 border-2 border-zinc-100 rounded-full animate-ping" />
                </div>
                <p className="text-zinc-400 font-mono text-xs uppercase tracking-widest animate-pulse">{loadingStep}</p>
              </motion.div>
            )}

            {result && !loading && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className={cn(
                  "border-2 rounded-2xl p-8 space-y-6 overflow-hidden relative",
                  getScoreColor(result.score),
                  getScoreBg(result.score)
                )}
              >
                <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono uppercase bg-zinc-900 border border-inherit px-2 py-0.5 rounded-full">
                        {result.input_type}
                      </span>
                      {result.warnings?.includes('low_source_count') && (
                        <div className="flex items-center gap-1 text-amber-500 font-mono text-[10px] uppercase">
                          <AlertTriangle className="w-3 h-3" />
                          Low source confidence
                        </div>
                      )}
                    </div>
                    <h3 className="text-2xl font-bold tracking-tight text-white">{result.summary}</h3>
                  </div>
                  <div className="flex flex-col items-end">
                    <span className="text-sm font-mono uppercase opacity-60">Trust Score</span>
                    <span className="text-6xl font-black italic">{result.score ?? 'N/A'}<span className="text-2xl not-italic">%</span></span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {result.sources?.length ? (
                    <div className="space-y-3">
                      <h4 className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 border-b border-zinc-800 pb-2">Verification Sources</h4>
                      <div className="space-y-2 max-h-60 overflow-y-auto pr-2 custom-scrollbar">
                        {result.sources?.map((src, i) => (
                          <a 
                            key={i} 
                            href={src.url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="block p-3 bg-zinc-900/50 border border-zinc-800 hover:border-zinc-500 rounded-lg transition-all group"
                          >
                            <div className="flex justify-between items-center">
                              <span className="text-xs font-bold truncate max-w-[200px]">{src.title}</span>
                              <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <span className={cn(
                                "text-[8px] uppercase font-mono px-1 rounded-sm",
                                src.category === 'official' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-zinc-700 text-zinc-400'
                              )}>
                                {src.category}
                              </span>
                              <span className="text-[8px] text-zinc-600 truncate">{src.url}</span>
                            </div>
                          </a>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="space-y-3">
                    <h4 className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 border-b border-zinc-800 pb-2">Internal Flags</h4>
                    <div className="space-y-2">
                       {result.warnings?.length ? result.warnings.map((w, i) => (
                         <div key={i} className="flex items-center gap-2 p-2 bg-zinc-900/50 rounded border border-zinc-800">
                           <AlertTriangle className={cn("w-3 h-3", w === 'source_timeout' ? 'text-rose-500' : 'text-amber-500')} />
                           <span className="text-[10px] font-mono uppercase">{w.replace(/_/g, ' ')}</span>
                         </div>
                       )) : (
                         <div className="flex items-center gap-2 p-2 bg-zinc-900/50 rounded border border-zinc-800">
                           <Check className="w-3 h-3 text-emerald-500" />
                           <span className="text-[10px] font-mono uppercase text-zinc-500">No critical warnings</span>
                         </div>
                       )}
                       
                       <button 
                        onClick={copyResult}
                        className="w-full flex items-center justify-center gap-2 p-3 bg-zinc-100 text-black rounded-lg font-bold text-xs hover:bg-white transition-all mt-4"
                       >
                         {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                         {copied ? 'COPIED' : 'COPY AS JSON'}
                       </button>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </section>
      </main>

      <AnimatePresence>
        {showHistory && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowHistory(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            />
            <motion.div 
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              className="fixed right-0 top-0 bottom-0 w-80 bg-[#0a0a0a] border-l border-zinc-800 z-[60] p-6 flex flex-col"
            >
              <div className="flex justify-between items-center mb-8">
                <h2 className="text-xl font-black uppercase tracking-tighter">Session history</h2>
                <button 
                  onClick={() => {
                    setHistory([]);
                    localStorage.removeItem('trustify_history');
                  }}
                  className="p-2 hover:bg-zinc-800 rounded-lg text-zinc-500 hover:text-rose-500 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto space-y-4 custom-scrollbar">
                {history.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-zinc-600 space-y-2 opacity-50">
                    <History className="w-8 h-8" />
                    <p className="font-mono text-[10px] uppercase">No recent scans</p>
                  </div>
                ) : history.map((h, i) => (
                  <div 
                    key={i} 
                    className="p-4 bg-zinc-900 border border-zinc-800 rounded-xl hover:border-zinc-600 transition-all cursor-pointer group"
                    onClick={() => { 
                      setResult(h); 
                      setShowHistory(false); 
                      setInput(''); 
                    }}
                  >
                    <div className="flex justify-between items-start mb-2">
                       <span className="text-[8px] font-mono px-1 border border-zinc-700 rounded uppercase">{h.input_type}</span>
                       <span className={cn("text-xs font-black italic", getScoreColor(h.score))}>{h.score ?? 'N/A'}%</span>
                    </div>
                    <p className="text-xs font-bold line-clamp-2 leading-tight group-hover:text-white transition-colors">
                      {h.summary}
                    </p>
                    <div className="flex items-center gap-1 mt-3 opacity-0 group-hover:opacity-100 transition-opacity">
                      <span className="text-[8px] font-mono uppercase text-zinc-500">Restore</span>
                      <ChevronRight className="w-2 h-2 text-zinc-500" />
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #27272a;
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #3f3f46;
        }
      `}</style>
    </div>
  );
}


export type InputType = 'text' | 'url';

export interface Source {
  title: string;
  url: string;
  category: 'official' | 'social';
  snippet?: string;
}

export interface VerificationResult {
  input_type: InputType;
  score: number | null;
  summary: string;
  sources: Source[];
  warnings: string[];
  safety_score?: number;
  domain_status?: string;
}

export interface TrustifyResponse {
  data: VerificationResult | null;
  error?: string;
  loading_step?: string;
}

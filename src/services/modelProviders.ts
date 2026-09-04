// AI provider catalogue.
//
// Every vendor call is routed through the `ai-proxy` edge function. Calling
// api.anthropic.com / api.cohere.ai / api.deepseek.com etc. directly from the
// browser is blocked by CORS preflight, which is what previously surfaced as
// the opaque "Failed to fetch" during key validation.

import { supabase } from '@/integrations/supabase/client';

export interface ModelOption {
  id: string;
  name: string;
  description?: string;
  available: boolean;
  contextWindow?: number;
}

export interface ModelProvider {
  id: string;
  name: string;
  description?: string;
  logoUrl?: string;
  /** Name of the API key in the user's collection. */
  apiKeyName: string;
  /** Where the user obtains a key. */
  keyUrl?: string;
  /** True when the provider needs no user-supplied key. */
  builtIn?: boolean;
  models: ModelOption[];
  testConnection: (apiKey: string) => Promise<boolean>;
  getModels: (apiKey: string) => Promise<ModelOption[]>;
}

export interface ProxyResult<T> {
  data?: T;
  error?: string;
}

/** Invokes the ai-proxy edge function and normalises transport failures. */
export async function callAiProxy<T>(payload: Record<string, unknown>): Promise<ProxyResult<T>> {
  try {
    const { data, error } = await supabase.functions.invoke('ai-proxy', { body: payload });

    if (error) {
      // Prefer the structured message the function returned over the SDK's
      // generic "non-2xx status code" wrapper.
      let message = error.message || 'The AI service could not be reached.';
      const context = (error as unknown as { context?: Response }).context;
      if (context && typeof context.text === 'function') {
        try {
          const parsed = JSON.parse(await context.text());
          if (parsed?.error) message = parsed.error;
        } catch {
          /* keep the SDK message */
        }
      }
      return { error: message };
    }

    if (data && typeof data === 'object' && 'error' in (data as Record<string, unknown>)) {
      return { error: String((data as Record<string, unknown>).error) };
    }

    return { data: data as T };
  } catch (e) {
    return {
      error: e instanceof Error ? e.message : 'The AI service could not be reached.',
    };
  }
}

/** Builds a provider whose validation and model discovery run server-side. */
function makeProvider(config: {
  id: string;
  name: string;
  description: string;
  apiKeyName: string;
  keyUrl?: string;
  builtIn?: boolean;
}): ModelProvider {
  return {
    ...config,
    models: [],
    async testConnection(apiKey: string) {
      const { data, error } = await callAiProxy<{ ok: boolean }>({
        action: 'test',
        provider: config.id,
        apiKey,
      });
      if (error) {
        console.warn(`[${config.id}] connection test failed: ${error}`);
        return false;
      }
      return Boolean(data?.ok);
    },
    async getModels(apiKey: string) {
      const { data, error } = await callAiProxy<{ models: ModelOption[] }>({
        action: 'models',
        provider: config.id,
        apiKey,
      });
      if (error) {
        console.warn(`[${config.id}] model discovery failed: ${error}`);
        return [];
      }
      return data?.models ?? [];
    },
  };
}

export const modelProviders: ModelProvider[] = [
  makeProvider({
    id: 'lovable',
    name: 'Built-in AI',
    description: 'Included Gemini and GPT models. No API key required.',
    apiKeyName: 'BUILT_IN',
    builtIn: true,
  }),
  makeProvider({
    id: 'openai',
    name: 'OpenAI',
    description: 'GPT models. Model list is read live from your account.',
    apiKeyName: 'OPENAI_API_KEY',
    keyUrl: 'https://platform.openai.com/api-keys',
  }),
  makeProvider({
    id: 'anthropic',
    name: 'Anthropic',
    description: 'Claude models, discovered live from the Anthropic models API.',
    apiKeyName: 'ANTHROPIC_API_KEY',
    keyUrl: 'https://console.anthropic.com/settings/keys',
  }),
  makeProvider({
    id: 'google',
    name: 'Google Gemini',
    description: 'Gemini models available to your Google AI Studio key.',
    apiKeyName: 'GOOGLE_API_KEY',
    keyUrl: 'https://aistudio.google.com/app/apikey',
  }),
  makeProvider({
    id: 'deepseek',
    name: 'DeepSeek',
    description: 'DeepSeek chat and reasoning models.',
    apiKeyName: 'DEEPSEEK_API_KEY',
    keyUrl: 'https://platform.deepseek.com/api_keys',
  }),
  makeProvider({
    id: 'cohere',
    name: 'Cohere',
    description: 'Command family models with live capability filtering.',
    apiKeyName: 'COHERE_API_KEY',
    keyUrl: 'https://dashboard.cohere.com/api-keys',
  }),
  makeProvider({
    id: 'groq',
    name: 'Groq',
    description: 'Very low latency inference for open-weight models.',
    apiKeyName: 'GROQ_API_KEY',
    keyUrl: 'https://console.groq.com/keys',
  }),
  makeProvider({
    id: 'xai',
    name: 'xAI (Grok)',
    description: 'Grok models from the xAI API.',
    apiKeyName: 'XAI_API_KEY',
    keyUrl: 'https://console.x.ai',
  }),
  makeProvider({
    id: 'mistral',
    name: 'Mistral',
    description: 'Mistral and Codestral models.',
    apiKeyName: 'MISTRAL_API_KEY',
    keyUrl: 'https://console.mistral.ai/api-keys',
  }),
  makeProvider({
    id: 'openrouter',
    name: 'OpenRouter',
    description: 'Aggregator exposing hundreds of models behind one key.',
    apiKeyName: 'OPENROUTER_API_KEY',
    keyUrl: 'https://openrouter.ai/keys',
  }),
  makeProvider({
    id: 'together',
    name: 'Together AI',
    description: 'Hosted open-weight models.',
    apiKeyName: 'TOGETHER_API_KEY',
    keyUrl: 'https://api.together.xyz/settings/api-keys',
  }),
];

export const getModelProvider = (providerId: string): ModelProvider | undefined =>
  modelProviders.find((p) => p.id === providerId);

/**
 * Returns the models the given key can actually use. An empty array means the
 * key could not be validated or the provider returned nothing usable.
 */
export async function fetchAvailableModels(
  providerId: string,
  apiKey: string,
): Promise<ModelOption[]> {
  const provider = getModelProvider(providerId);
  if (!provider) return [];
  return provider.getModels(apiKey);
}

/**
 * Validates a key and returns the live model list together with the provider's
 * own error text, so the UI can show why a key was rejected instead of a
 * generic failure.
 */
export async function validateProvider(
  providerId: string,
  apiKey: string,
): Promise<{ ok: boolean; models: ModelOption[]; error?: string }> {
  const provider = getModelProvider(providerId);
  if (!provider) return { ok: false, models: [], error: `Unknown provider "${providerId}".` };

  const { data, error } = await callAiProxy<{ models: ModelOption[] }>({
    action: 'models',
    provider: providerId,
    apiKey,
  });

  if (error) return { ok: false, models: [], error };
  const models = data?.models ?? [];
  if (!models.length) {
    return { ok: false, models: [], error: 'The key was accepted but no usable chat models were returned.' };
  }
  return { ok: true, models };
}

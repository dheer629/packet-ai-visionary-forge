import { callAiProxy, getModelProvider } from './modelProviders';

interface AIRequestOptions {
  providerId: string;
  apiKey: string;
  modelId: string;
  prompt?: string;
  messages?: { role: 'system' | 'user' | 'assistant'; content: string }[];
  maxTokens?: number;
  temperature?: number;
}

export interface AIResponse {
  text: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  error?: string;
}

/** Reads the stored key/model settings for a provider. */
export const getProviderSettings = (providerId: string) => {
  const savedKeys = localStorage.getItem('nettracer-api-keys');
  if (!savedKeys) return null;

  try {
    const apiKeys = JSON.parse(savedKeys);
    return Array.isArray(apiKeys)
      ? apiKeys.find((key: { providerId: string }) => key.providerId === providerId)
      : null;
  } catch {
    return null;
  }
};

/**
 * Sends one chat request. The vendor call happens inside the `ai-proxy` edge
 * function, so the browser never performs a cross-origin request that the
 * provider would reject at preflight.
 */
export async function callAIModel(options: AIRequestOptions): Promise<AIResponse> {
  const {
    providerId,
    apiKey,
    modelId,
    prompt,
    messages,
    maxTokens = 1500,
    temperature = 0.4,
  } = options;

  const provider = getModelProvider(providerId);
  if (!provider) {
    return { text: '', error: `Unknown AI provider "${providerId}".` };
  }
  if (!provider.builtIn && !apiKey) {
    return { text: '', error: `No API key saved for ${provider.name}.` };
  }
  if (!modelId) {
    return { text: '', error: `No model selected for ${provider.name}.` };
  }

  const { data, error } = await callAiProxy<{
    text: string;
    usage?: { promptTokens: number; completionTokens: number; totalTokens: number };
  }>({
    action: 'chat',
    provider: providerId,
    apiKey,
    model: modelId,
    prompt,
    messages,
    maxTokens,
    temperature,
  });

  if (error) return { text: '', error };
  return { text: data?.text ?? '', usage: data?.usage };
}

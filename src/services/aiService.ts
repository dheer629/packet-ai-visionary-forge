
import { modelProviders } from './modelProviders';

interface AIRequestOptions {
  providerId: string;
  apiKey: string;
  modelId: string;
  prompt: string;
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

// Get the API key and selected model for a provider
export const getProviderSettings = (providerId: string) => {
  const savedKeys = localStorage.getItem('nettracer-api-keys');
  if (!savedKeys) return null;
  
  const apiKeys = JSON.parse(savedKeys);
  return apiKeys.find((key: any) => key.providerId === providerId);
};

export async function callAIModel(options: AIRequestOptions): Promise<AIResponse> {
  const { providerId, apiKey, modelId, prompt, maxTokens = 1000, temperature = 0.7 } = options;
  
  // Find the provider
  const provider = modelProviders.find(p => p.id === providerId);
  if (!provider) {
    return { text: '', error: 'Provider not found' };
  }
  
  switch (providerId) {
    case 'openai':
      return callOpenAI(apiKey, modelId, prompt, maxTokens, temperature);
    case 'anthropic':
      return callAnthropic(apiKey, modelId, prompt, maxTokens, temperature);
    case 'deepseek':
      return callDeepseek(apiKey, modelId, prompt, maxTokens, temperature);
    case 'google':
      return callGoogle(apiKey, modelId, prompt, maxTokens, temperature);
    default:
      return { text: '', error: 'Unsupported provider' };
  }
}

async function callOpenAI(
  apiKey: string, 
  modelId: string, 
  prompt: string, 
  maxTokens: number, 
  temperature: number
): Promise<AIResponse> {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: maxTokens,
        temperature: temperature,
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      return { text: '', error: errorData.error?.message || 'OpenAI API error' };
    }
    
    const data = await response.json();
    return {
      text: data.choices[0]?.message?.content || '',
      usage: {
        promptTokens: data.usage?.prompt_tokens || 0,
        completionTokens: data.usage?.completion_tokens || 0,
        totalTokens: data.usage?.total_tokens || 0,
      }
    };
  } catch (error) {
    console.error('OpenAI API error:', error);
    return { text: '', error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

async function callAnthropic(
  apiKey: string, 
  modelId: string, 
  prompt: string, 
  maxTokens: number, 
  temperature: number
): Promise<AIResponse> {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: maxTokens,
        temperature: temperature,
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      return { text: '', error: errorData.error?.message || 'Anthropic API error' };
    }
    
    const data = await response.json();
    return {
      text: data.content?.[0]?.text || '',
      usage: {
        promptTokens: data.usage?.input_tokens || 0,
        completionTokens: data.usage?.output_tokens || 0,
        totalTokens: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0),
      }
    };
  } catch (error) {
    console.error('Anthropic API error:', error);
    return { text: '', error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

async function callDeepseek(
  apiKey: string, 
  modelId: string, 
  prompt: string, 
  maxTokens: number, 
  temperature: number
): Promise<AIResponse> {
  try {
    const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: modelId,
        messages: [{
          role: 'user',
          content: prompt
        }],
        max_tokens: maxTokens,
        temperature: temperature,
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      return { text: '', error: errorData.error?.message || 'Deepseek API error' };
    }
    
    const data = await response.json();
    return {
      text: data.choices?.[0]?.message?.content || '',
      usage: {
        promptTokens: data.usage?.prompt_tokens || 0,
        completionTokens: data.usage?.completion_tokens || 0,
        totalTokens: data.usage?.total_tokens || 0,
      }
    };
  } catch (error) {
    console.error('Deepseek API error:', error);
    return { text: '', error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

async function callGoogle(
  apiKey: string, 
  modelId: string, 
  prompt: string, 
  maxTokens: number, 
  temperature: number
): Promise<AIResponse> {
  try {
    const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + modelId + ':generateContent', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey,
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              {
                text: prompt
              }
            ]
          }
        ],
        generationConfig: {
          temperature: temperature,
          maxOutputTokens: maxTokens,
        }
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      return { text: '', error: errorData.error?.message || 'Google API error' };
    }
    
    const data = await response.json();
    return {
      text: data.candidates?.[0]?.content?.parts?.[0]?.text || '',
      usage: {
        promptTokens: data.usageMetadata?.promptTokenCount || 0,
        completionTokens: data.usageMetadata?.candidatesTokenCount || 0,
        totalTokens: (data.usageMetadata?.promptTokenCount || 0) + (data.usageMetadata?.candidatesTokenCount || 0),
      }
    };
  } catch (error) {
    console.error('Google API error:', error);
    return { text: '', error: error instanceof Error ? error.message : 'Unknown error' };
  }
}


// Model provider types and constants
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
  apiKeyName: string;  // Name of the API key in user's collection
  models: ModelOption[];
  testConnection: (apiKey: string) => Promise<boolean>;
}

// Available model providers
export const modelProviders: ModelProvider[] = [
  {
    id: 'openai',
    name: 'OpenAI',
    description: 'OpenAI API provides access to GPT models like GPT-4o, GPT-4 and GPT-3.5',
    apiKeyName: 'OPENAI_API_KEY',
    models: [
      { id: 'gpt-4o', name: 'GPT-4o', description: 'Most capable multimodal model for vision and language tasks', available: true, contextWindow: 128000 },
      { id: 'gpt-4o-mini', name: 'GPT-4o-mini', description: 'Efficient multimodal model with strong performance', available: true, contextWindow: 128000 },
      { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', description: 'Improved version of GPT-4', available: true, contextWindow: 128000 },
      { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Fast and efficient language model', available: true, contextWindow: 16385 },
    ],
    testConnection: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.openai.com/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('OpenAI connection test failed:', error);
        return false;
      }
    }
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    description: 'Anthropic provides Claude models known for their safety and helpful behaviors',
    apiKeyName: 'ANTHROPIC_API_KEY',
    models: [
      { id: 'claude-3-opus', name: 'Claude 3 Opus', description: 'Most powerful Claude model', available: true, contextWindow: 200000 },
      { id: 'claude-3-sonnet', name: 'Claude 3 Sonnet', description: 'Balanced Claude model', available: true, contextWindow: 180000 },
      { id: 'claude-3-haiku', name: 'Claude 3 Haiku', description: 'Fast, efficient Claude model', available: true, contextWindow: 150000 },
    ],
    testConnection: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.anthropic.com/v1/models', {
          method: 'GET',
          headers: {
            'x-api-key': apiKey,
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Anthropic connection test failed:', error);
        return false;
      }
    }
  },
  {
    id: 'deepseek',
    name: 'Deepseek',
    description: 'Deepseek provides state-of-the-art language models',
    apiKeyName: 'DEEPSEEK_API_KEY',
    models: [
      { id: 'deepseek-coder', name: 'Deepseek Coder', description: 'Specialized for code generation', available: true },
      { id: 'deepseek-chat', name: 'Deepseek Chat', description: 'General-purpose chat model', available: true },
    ],
    testConnection: async (apiKey: string) => {
      // Mock implementation since Deepseek API details may differ
      return Promise.resolve(apiKey.length > 10);
    }
  },
  {
    id: 'google',
    name: 'Google AI (Gemini)',
    description: 'Google AI provides access to Gemini models',
    apiKeyName: 'GOOGLE_API_KEY',
    models: [
      { id: 'gemini-pro', name: 'Gemini Pro', description: 'Multimodal model for text and vision tasks', available: true },
      { id: 'gemini-ultra', name: 'Gemini Ultra', description: 'Advanced multimodal model with superior reasoning', available: true },
    ],
    testConnection: async (apiKey: string) => {
      // Mock implementation for Google AI
      return Promise.resolve(apiKey.length > 10);
    }
  }
];

// Function to get a model provider by ID
export function getModelProvider(providerId: string): ModelProvider | undefined {
  return modelProviders.find(provider => provider.id === providerId);
}

// Function to fetch real-time available models for a provider
export async function fetchAvailableModels(providerId: string, apiKey: string): Promise<ModelOption[]> {
  const provider = getModelProvider(providerId);
  if (!provider) return [];
  
  try {
    const isConnected = await provider.testConnection(apiKey);
    if (!isConnected) return provider.models.map(model => ({ ...model, available: false }));
    
    // In a real implementation, you would make API calls to get the actual available models
    // For now, we'll return the predefined models with available = true
    return provider.models;
  } catch (error) {
    console.error(`Failed to fetch models for ${providerId}:`, error);
    return provider.models.map(model => ({ ...model, available: false }));
  }
}

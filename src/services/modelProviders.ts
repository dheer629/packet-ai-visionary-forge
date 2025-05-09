
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
  getModels?: (apiKey: string) => Promise<ModelOption[]>;
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
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.openai.com/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch OpenAI models');
        }
        
        const data = await response.json();
        
        // Filter relevant models
        const relevantModels = [
          { id: 'gpt-4o', name: 'GPT-4o', description: 'Most capable multimodal model for vision and language tasks', contextWindow: 128000 },
          { id: 'gpt-4o-mini', name: 'GPT-4o-mini', description: 'Efficient multimodal model with strong performance', contextWindow: 128000 },
          { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', description: 'Improved version of GPT-4', contextWindow: 128000 },
          { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Fast and efficient language model', contextWindow: 16385 },
        ];
        
        // Check which models are available to this API key
        const availableModels = data.data.map((model: any) => model.id);
        
        return relevantModels.map(model => ({
          ...model,
          available: availableModels.includes(model.id),
        }));
      } catch (error) {
        console.error('Failed to fetch OpenAI models:', error);
        // Return default models with unknown availability
        return [
          { id: 'gpt-4o', name: 'GPT-4o', description: 'Most capable multimodal model for vision and language tasks', available: false, contextWindow: 128000 },
          { id: 'gpt-4o-mini', name: 'GPT-4o-mini', description: 'Efficient multimodal model with strong performance', available: false, contextWindow: 128000 },
          { id: 'gpt-4-turbo', name: 'GPT-4 Turbo', description: 'Improved version of GPT-4', available: false, contextWindow: 128000 },
          { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo', description: 'Fast and efficient language model', available: false, contextWindow: 16385 },
        ];
      }
    }
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    description: 'Anthropic provides Claude models known for their safety and helpful behaviors',
    apiKeyName: 'ANTHROPIC_API_KEY',
    models: [
      { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', description: 'Most powerful Claude model', available: true, contextWindow: 200000 },
      { id: 'claude-3-sonnet-20240229', name: 'Claude 3 Sonnet', description: 'Balanced Claude model', available: true, contextWindow: 180000 },
      { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', description: 'Fast, efficient Claude model', available: true, contextWindow: 150000 },
    ],
    testConnection: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.anthropic.com/v1/models', {
          method: 'GET',
          headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Anthropic connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.anthropic.com/v1/models', {
          method: 'GET',
          headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch Anthropic models');
        }
        
        const data = await response.json();
        
        const relevantModels = [
          { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', description: 'Most powerful Claude model', contextWindow: 200000 },
          { id: 'claude-3-sonnet-20240229', name: 'Claude 3 Sonnet', description: 'Balanced Claude model', contextWindow: 180000 },
          { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', description: 'Fast, efficient Claude model', contextWindow: 150000 },
        ];
        
        // Check which models are available
        const availableModels = data.models.map((model: any) => model.id);
        
        return relevantModels.map(model => ({
          ...model,
          available: availableModels.includes(model.id),
        }));
      } catch (error) {
        console.error('Failed to fetch Anthropic models:', error);
        return [
          { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', description: 'Most powerful Claude model', available: false, contextWindow: 200000 },
          { id: 'claude-3-sonnet-20240229', name: 'Claude 3 Sonnet', description: 'Balanced Claude model', available: false, contextWindow: 180000 },
          { id: 'claude-3-haiku-20240307', name: 'Claude 3 Haiku', description: 'Fast, efficient Claude model', available: false, contextWindow: 150000 },
        ];
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
      try {
        const response = await fetch('https://api.deepseek.com/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Deepseek connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.deepseek.com/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch Deepseek models');
        }
        
        const data = await response.json();
        const availableModels = data.data.map((model: any) => model.id);
        
        return [
          { id: 'deepseek-coder', name: 'Deepseek Coder', description: 'Specialized for code generation', available: availableModels.includes('deepseek-coder') },
          { id: 'deepseek-chat', name: 'Deepseek Chat', description: 'General-purpose chat model', available: availableModels.includes('deepseek-chat') },
        ];
      } catch (error) {
        console.error('Failed to fetch Deepseek models:', error);
        return [
          { id: 'deepseek-coder', name: 'Deepseek Coder', description: 'Specialized for code generation', available: false },
          { id: 'deepseek-chat', name: 'Deepseek Chat', description: 'General-purpose chat model', available: false },
        ];
      }
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
      try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Google AI connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch Google AI models');
        }
        
        const data = await response.json();
        const availableModels = data.models.map((model: any) => model.name.split('/').pop());
        
        return [
          { id: 'gemini-pro', name: 'Gemini Pro', description: 'Multimodal model for text and vision tasks', available: availableModels.includes('gemini-pro') },
          { id: 'gemini-ultra', name: 'Gemini Ultra', description: 'Advanced multimodal model with superior reasoning', available: availableModels.includes('gemini-ultra') },
        ];
      } catch (error) {
        console.error('Failed to fetch Google AI models:', error);
        return [
          { id: 'gemini-pro', name: 'Gemini Pro', description: 'Multimodal model for text and vision tasks', available: false },
          { id: 'gemini-ultra', name: 'Gemini Ultra', description: 'Advanced multimodal model with superior reasoning', available: false },
        ];
      }
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
    if (!isConnected) {
      return provider.models.map(model => ({ ...model, available: false }));
    }
    
    // If provider has a getModels method, use it
    if (provider.getModels) {
      return await provider.getModels(apiKey);
    }
    
    // In a real implementation, you would make API calls to get the actual available models
    // For now, we'll return the predefined models with available = true
    return provider.models;
  } catch (error) {
    console.error(`Failed to fetch models for ${providerId}:`, error);
    return provider.models.map(model => ({ ...model, available: false }));
  }
}

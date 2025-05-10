
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
    id: 'cohere',
    name: 'Cohere',
    description: 'Cohere provides models specialized in text understanding and generation',
    apiKeyName: 'COHERE_API_KEY',
    models: [
      { id: 'command-r-plus', name: 'Command R+', description: 'Most powerful Command model', available: true, contextWindow: 128000 },
      { id: 'command-r', name: 'Command R', description: 'Balanced performance and capabilities', available: true, contextWindow: 128000 },
      { id: 'command-light', name: 'Command Light', description: 'Fast, lightweight model', available: true, contextWindow: 128000 },
    ],
    testConnection: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.cohere.ai/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Cohere connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.cohere.ai/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch Cohere models');
        }
        
        const data = await response.json();
        
        const relevantModels = [
          { id: 'command-r-plus', name: 'Command R+', description: 'Most powerful Command model', contextWindow: 128000 },
          { id: 'command-r', name: 'Command R', description: 'Balanced performance and capabilities', contextWindow: 128000 },
          { id: 'command-light', name: 'Command Light', description: 'Fast, lightweight model', contextWindow: 128000 },
        ];
        
        // Check which models are available
        const availableModels = data.models?.map((model: any) => model.id) || [];
        
        return relevantModels.map(model => ({
          ...model,
          available: availableModels.includes(model.id),
        }));
      } catch (error) {
        console.error('Failed to fetch Cohere models:', error);
        return [
          { id: 'command-r-plus', name: 'Command R+', description: 'Most powerful Command model', available: false, contextWindow: 128000 },
          { id: 'command-r', name: 'Command R', description: 'Balanced performance and capabilities', available: false, contextWindow: 128000 },
          { id: 'command-light', name: 'Command Light', description: 'Fast, lightweight model', available: false, contextWindow: 128000 },
        ];
      }
    }
  },
  {
    id: 'groq',
    name: 'Groq',
    description: 'Groq provides extremely fast inference for LLM models',
    apiKeyName: 'GROQ_API_KEY',
    models: [
      { id: 'llama3-70b-8192', name: 'LLama 3 70B', description: 'Most powerful LLama 3 model', available: true, contextWindow: 8192 },
      { id: 'llama3-8b-8192', name: 'LLama 3 8B', description: 'Efficient LLama 3 model', available: true, contextWindow: 8192 },
      { id: 'mixtral-8x7b-32768', name: 'Mixtral 8x7B', description: 'Powerful mixture of experts model', available: true, contextWindow: 32768 },
    ],
    testConnection: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.groq.com/openai/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        return response.status === 200;
      } catch (error) {
        console.error('Groq connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        const response = await fetch('https://api.groq.com/openai/v1/models', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch Groq models');
        }
        
        const data = await response.json();
        
        const relevantModels = [
          { id: 'llama3-70b-8192', name: 'LLama 3 70B', description: 'Most powerful LLama 3 model', contextWindow: 8192 },
          { id: 'llama3-8b-8192', name: 'LLama 3 8B', description: 'Efficient LLama 3 model', contextWindow: 8192 },
          { id: 'mixtral-8x7b-32768', name: 'Mixtral 8x7B', description: 'Powerful mixture of experts model', contextWindow: 32768 },
        ];
        
        // Check which models are available
        const availableModels = data.data?.map((model: any) => model.id) || [];
        
        return relevantModels.map(model => ({
          ...model,
          available: availableModels.includes(model.id),
        }));
      } catch (error) {
        console.error('Failed to fetch Groq models:', error);
        return [
          { id: 'llama3-70b-8192', name: 'LLama 3 70B', description: 'Most powerful LLama 3 model', available: false, contextWindow: 8192 },
          { id: 'llama3-8b-8192', name: 'LLama 3 8B', description: 'Efficient LLama 3 model', available: false, contextWindow: 8192 },
          { id: 'mixtral-8x7b-32768', name: 'Mixtral 8x7B', description: 'Powerful mixture of experts model', available: false, contextWindow: 32768 },
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
        const availableModels = data.data?.map((model: any) => model.id) || [];
        
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
        // Fix: Use the key parameter correctly in the URL
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        
        console.log('Google API test response:', response.status);
        return response.status === 200;
      } catch (error) {
        console.error('Google AI connection test failed:', error);
        return false;
      }
    },
    getModels: async (apiKey: string) => {
      try {
        // Fix: Use the key parameter correctly in the URL
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });
        
        if (!response.ok) {
          console.error('Google API response not OK:', await response.text());
          throw new Error('Failed to fetch Google AI models');
        }
        
        const data = await response.json();
        // Extract model names and check if gemini models are available
        const availableModels = data.models?.map((model: any) => {
          const modelName = model.name.split('/').pop();
          return modelName;
        }) || [];
        
        console.log('Available Google models:', availableModels);
        
        return [
          { id: 'gemini-pro', name: 'Gemini Pro', description: 'Multimodal model for text and vision tasks', available: availableModels.some((m: string) => m.includes('gemini-pro')) },
          { id: 'gemini-ultra', name: 'Gemini Ultra', description: 'Advanced multimodal model with superior reasoning', available: availableModels.some((m: string) => m.includes('gemini-ultra')) },
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
    console.log(`Testing connection for provider: ${providerId}`);
    const isConnected = await provider.testConnection(apiKey);
    console.log(`Connection test for ${providerId}: ${isConnected ? 'SUCCESS' : 'FAILED'}`);
    
    if (!isConnected) {
      return provider.models.map(model => ({ ...model, available: false }));
    }
    
    // If provider has a getModels method, use it
    if (provider.getModels) {
      console.log(`Fetching models for ${providerId}...`);
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

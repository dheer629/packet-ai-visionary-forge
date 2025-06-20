
import { callAIModel } from '../services/aiService';
import { ProcessedData } from './packetEnhancer';

export const applyAIEnhancement = async (
  analysisData: ProcessedData,
  onAiEnrichmentChange: (value: boolean) => void,
  showToast: (toast: any) => void
): Promise<ProcessedData> => {
  // Check if we have API keys available for AI enhancement
  const apiKeys = JSON.parse(localStorage.getItem('nettracer-api-keys') || '[]');
  let aiProviderKey = null;
  let aiProvider = null;
  
  // Check for available AI providers in this order of preference
  const preferredProviders = ['openai', 'anthropic', 'cohere', 'groq', 'deepseek'];
  
  for (const providerId of preferredProviders) {
    const providerKey = apiKeys.find((key: any) => key.providerId === providerId && key.value);
    if (providerKey) {
      aiProviderKey = providerKey;
      aiProvider = providerId;
      break;
    }
  }
  
  // AI enhancement if keys are available
  if (aiProviderKey && aiProviderKey.value && aiProviderKey.selectedModel) {
    try {
      onAiEnrichmentChange(true);
      showToast({
        title: "AI Enhancement Started",
        description: `Using ${aiProviderKey.name} to enhance analysis`,
      });
      
      // Generate a summary of the packet capture using the selected model
      const packetSummary = `${analysisData.summary.totalPackets} packets captured between ${analysisData.summary.startTime} and ${analysisData.summary.endTime}. 
      ${analysisData.summary.protocolCounts?.map((p: any) => `${p.protocol}: ${p.count}`).join(', ') || ''}. 
      IP addresses involved: ${analysisData.summary.topIPs?.slice(0, 5).map((ip: any) => ip.address).join(', ') || ''}`;
      
      const aiResponse = await callAIModel({
        providerId: aiProvider!,
        apiKey: aiProviderKey.value,
        modelId: aiProviderKey.selectedModel,
        prompt: `Analyze this network capture summary and provide insights: ${packetSummary}. Identify any potential security concerns, unusual patterns, or notable traffic characteristics.`,
        maxTokens: 500,
        temperature: 0.3
      });
      
      if (aiResponse.error) {
        console.error('AI enrichment error:', aiResponse.error);
        showToast({
          title: "AI Enhancement Failed",
          description: aiResponse.error,
          variant: "destructive"
        });
      } else {
        // Add AI insights to the analysis data
        analysisData.aiEnriched = true;
        analysisData.aiProvider = aiProviderKey.name;
        analysisData.aiInsights = aiResponse.text;
        console.log('Analysis enriched with AI from provider:', aiProviderKey.name);
        
        showToast({
          title: "AI Enhancement Complete",
          description: `Analysis enhanced with ${aiProviderKey.name}`,
        });
      }
    } catch (error) {
      console.error('Error processing with AI:', error);
      showToast({
        title: "AI Enhancement Failed",
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: "destructive"
      });
    } finally {
      onAiEnrichmentChange(false);
    }
  }
  
  return analysisData;
};

export const createFallbackData = (file: File): ProcessedData => {
  return {
    packets: Array.from({ length: 10 }).map((_, idx) => ({
      number: idx + 1,
      time: (idx * 0.001).toFixed(6),
      source: 'Unknown',
      destination: 'Unknown',
      protocol: 'Unknown',
      length: 78,
      info: 'Unknown Packet'
    })),
    summary: {
      totalPackets: 10,
      ipAddresses: 0,
      conversationCount: 0,
      startTime: '0.000000',
      endTime: '0.010000',
      protocolCounts: [{ protocol: 'Unknown', count: 10 }]
    },
    protocolData: [{ name: 'Unknown', value: 10 }],
    timeSeriesData: Array(10).fill(0).map((_, i) => ({ time: `${i * 10}%`, value: 1 })),
    conversations: [],
    filename: file.name,
    size: file.size,
    timestamp: Date.now()
  };
};

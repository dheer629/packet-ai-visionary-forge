
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { AlertTriangle, CheckCircle, Search, Info } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

interface AIInsightsProps {
  data: any;
}

const AIInsights: React.FC<AIInsightsProps> = ({ data }) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [insights, setInsights] = useState<any>(null);

  const runAIAnalysis = () => {
    setIsAnalyzing(true);
    // Simulate AI analysis
    setTimeout(() => {
      setIsAnalyzing(false);
      // Mock AI insights data
      setInsights({
        timestamp: new Date().toISOString(),
        summary: "This PCAP shows typical home network activity with some web browsing, DNS queries, and periodic system updates. No significant security concerns detected.",
        findings: [
          {
            type: "info",
            title: "Normal Web Browsing Activity",
            description: "Standard HTTP and HTTPS traffic to common web domains detected."
          },
          {
            type: "warning",
            title: "Unusual Port Activity",
            description: "Traffic detected on uncommon port 4782. This might be legitimate but worth investigating."
          },
          {
            type: "success",
            title: "No Malicious Signatures",
            description: "No known malware communication patterns were identified in the traffic."
          }
        ],
        recommendations: [
          "Investigate traffic on port 4782 to verify it's authorized",
          "Consider enabling TLS 1.3 for all secure connections",
          "Normal amount of DNS queries observed, no DNS tunneling detected"
        ]
      });
    }, 2000);
  };

  useEffect(() => {
    // Reset insights when new data comes in
    setInsights(null);
  }, [data]);

  const renderFindingIcon = (type: string) => {
    switch (type) {
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
      case 'success': 
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'info':
        return <Info className="h-5 w-5 text-cyber-primary" />;
      default:
        return <Info className="h-5 w-5 text-cyber-primary" />;
    }
  };

  return (
    <div className="cyber-box">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold cyber-text">AI Insights</h2>
        
        <Button
          onClick={runAIAnalysis}
          disabled={isAnalyzing || !data}
          className="bg-cyber-secondary hover:bg-cyber-secondary/80 text-white"
        >
          {isAnalyzing ? (
            <>Analyzing<span className="ml-1 animate-pulse">...</span></>
          ) : (
            <>
              <Search className="mr-2 h-4 w-4" />
              Run AI Analysis
            </>
          )}
        </Button>
      </div>
      
      {!data && (
        <div className="text-center py-8 text-cyber-foreground/70">
          <p>Upload a PCAP file to analyze</p>
        </div>
      )}
      
      {data && !insights && !isAnalyzing && (
        <div className="text-center py-8 border border-dashed border-cyber-border rounded-md">
          <p className="text-cyber-foreground/70">Click "Run AI Analysis" to generate insights</p>
        </div>
      )}
      
      {isAnalyzing && (
        <div className="space-y-2 py-4">
          <div className="h-4 bg-cyber-muted rounded animate-pulse"></div>
          <div className="h-4 bg-cyber-muted rounded animate-pulse w-5/6"></div>
          <div className="h-4 bg-cyber-muted rounded animate-pulse w-4/6"></div>
        </div>
      )}
      
      {insights && (
        <div className="space-y-4">
          <Card className="cyber-box bg-cyber-background border border-cyber-border">
            <p className="text-sm text-cyber-foreground/90">{insights.summary}</p>
          </Card>
          
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-cyber-accent">Key Findings</h3>
            
            {insights.findings.map((finding: any, index: number) => (
              <div key={index} className="flex items-start p-3 border-l-2 border-cyber-border bg-cyber-muted bg-opacity-30 rounded">
                <div className="mr-3">
                  {renderFindingIcon(finding.type)}
                </div>
                <div>
                  <h4 className="text-sm font-medium">{finding.title}</h4>
                  <p className="text-xs text-cyber-foreground/70">{finding.description}</p>
                </div>
              </div>
            ))}
          </div>
          
          <div>
            <h3 className="text-sm font-medium text-cyber-accent mb-2">Recommendations</h3>
            <ul className="space-y-1">
              {insights.recommendations.map((rec: string, index: number) => (
                <li key={index} className="text-sm flex items-center">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyber-primary mr-2"></span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>
          
          <Separator className="bg-cyber-border" />
          
          <div className="text-xs text-cyber-foreground/50">
            Analysis completed on {new Date(insights.timestamp).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
};

export default AIInsights;

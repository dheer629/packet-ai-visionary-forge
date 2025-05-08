
import React from 'react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

interface ChartProps {
  type: 'area' | 'bar' | 'pie';
  data: any[];
  colors?: string[];
  title: string;
  dataKey?: string;
  xAxisKey?: string;
}

const VisualizationChart: React.FC<ChartProps> = ({ 
  type, 
  data, 
  colors = ['#06b6d4', '#a855f7', '#2dd4bf', '#f97316'], 
  title,
  dataKey = 'value',
  xAxisKey = 'name'
}) => {
  const renderChart = () => {
    switch (type) {
      case 'area':
        return (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors[0]} stopOpacity={0.8} />
                  <stop offset="95%" stopColor={colors[0]} stopOpacity={0.1} />
                </linearGradient>
              </defs>
              <XAxis 
                dataKey={xAxisKey} 
                stroke="#64748b" 
                fontSize={10} 
                tick={{ fill: '#94a3b8' }}
              />
              <YAxis stroke="#64748b" fontSize={10} tick={{ fill: '#94a3b8' }} />
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  borderColor: '#334155',
                  color: '#f8fafc'
                }}
              />
              <Area 
                type="monotone" 
                dataKey={dataKey} 
                stroke={colors[0]} 
                fillOpacity={1} 
                fill="url(#colorValue)" 
              />
            </AreaChart>
          </ResponsiveContainer>
        );
      
      case 'bar':
        return (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                dataKey={xAxisKey} 
                stroke="#64748b" 
                fontSize={10} 
                tick={{ fill: '#94a3b8' }}
              />
              <YAxis stroke="#64748b" fontSize={10} tick={{ fill: '#94a3b8' }} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  borderColor: '#334155',
                  color: '#f8fafc'
                }}
              />
              <Bar dataKey={dataKey} fill={colors[0]} />
            </BarChart>
          </ResponsiveContainer>
        );
      
      case 'pie':
        return (
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                labelLine={false}
                outerRadius={80}
                fill="#8884d8"
                dataKey={dataKey}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  borderColor: '#334155',
                  color: '#f8fafc'
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        );
      
      default:
        return <div>Chart type not supported</div>;
    }
  };

  return (
    <div className="cyber-box">
      <h3 className="text-sm font-medium mb-2 cyber-text">{title}</h3>
      {renderChart()}
    </div>
  );
};

export default VisualizationChart;

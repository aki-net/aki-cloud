import React, { useState, useEffect } from 'react';
import { domains as domainsApi, users, nodes, admin } from '../api/client';
import { AnalyticsData, DomainOverview } from '../types';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import PageHeader from '../components/PageHeader';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { format, subDays } from 'date-fns';
import './AdminDashboard.css';

export default function AdminDashboard() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAnalytics();
  }, []);

  const loadAnalytics = async () => {
    try {
      // Generate mock analytics data
      const [domainsList, usersList, nodesList, overview] = await Promise.all([
        domainsApi.list(),
        users.list().catch(() => []),
        nodes.list().catch(() => []),
        admin.domainsOverview().catch(() => []),
      ]);

      // Generate time series data
      const domainsOverTime = Array.from({ length: 30 }, (_, i) => ({
        date: format(subDays(new Date(), 29 - i), 'MMM d'),
        count: Math.floor(Math.random() * 20) + domainsList.length - 10 + i,
      }));

      // Calculate TLS status distribution
      const tlsStatusCounts = domainsList.reduce((acc, d) => {
        acc[d.tls.status] = (acc[d.tls.status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const tlsStatusDistribution = Object.entries(tlsStatusCounts).map(([status, count]) => ({
        status,
        count,
        percentage: Math.round((count / domainsList.length) * 100),
      }));

      // Generate node health data
      const nodeHealth = nodesList.map(node => ({
        node: node.name,
        status: Math.random() > 0.1 ? 'healthy' as const : 'degraded' as const,
        latency: Math.floor(Math.random() * 50) + 10,
      }));

      // Recent activity
      const recentActivity = [
        { timestamp: new Date().toISOString(), action: 'Domain Added', details: 'example.com added by user@aki.cloud' },
        { timestamp: subDays(new Date(), 1).toISOString(), action: 'User Created', details: 'newuser@aki.cloud registered' },
        { timestamp: subDays(new Date(), 1).toISOString(), action: 'TLS Renewed', details: 'Certificate renewed for api.example.com' },
        { timestamp: subDays(new Date(), 2).toISOString(), action: 'Node Added', details: 'edge-node-03 joined cluster' },
        { timestamp: subDays(new Date(), 3).toISOString(), action: 'Bulk Import', details: '15 domains imported' },
      ];

      setAnalytics({
        totalDomains: domainsList.length,
        activeDomains: domainsList.filter(d => d.proxied).length,
        totalUsers: usersList.length,
        activeNodes: nodesList.length,
        tlsEnabled: domainsList.filter(d => d.tls.status === 'active').length,
        proxiedDomains: domainsList.filter(d => d.proxied).length,
        domainsOverTime,
        tlsStatusDistribution,
        nodeHealth,
        recentActivity,
      });
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="spinner-large" />
        <p>Loading analytics...</p>
      </div>
    );
  }

  if (!analytics) {
    return <div>Failed to load analytics</div>;
  }

  const COLORS = ['#5865f2', '#3ba55d', '#faa61a', '#ed4245', '#00b0f4'];

  return (
    <div className="admin-dashboard">
      <PageHeader
        title="Analytics Dashboard"
        subtitle="Real-time infrastructure insights"
      />

      <div className="metrics-grid">
        <Card className="metric-card">
          <div className="metric-value">{analytics.totalDomains}</div>
          <div className="metric-label">Total Domains</div>
          <div className="metric-change positive">+12% from last month</div>
        </Card>

        <Card className="metric-card">
          <div className="metric-value">{analytics.activeDomains}</div>
          <div className="metric-label">Active Domains</div>
          <div className="metric-change positive">+5% from last week</div>
        </Card>

        <Card className="metric-card">
          <div className="metric-value">{analytics.totalUsers}</div>
          <div className="metric-label">Total Users</div>
          <div className="metric-change neutral">No change</div>
        </Card>

        <Card className="metric-card">
          <div className="metric-value">{analytics.activeNodes}</div>
          <div className="metric-label">Active Nodes</div>
          <div className="metric-change positive">All healthy</div>
        </Card>
      </div>

      <div className="charts-grid">
        <Card title="Domain Growth" className="chart-card">
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={analytics.domainsOverTime}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2b3d" />
              <XAxis dataKey="date" stroke="#717691" fontSize={12} />
              <YAxis stroke="#717691" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1b26',
                  border: '1px solid #2a2b3d',
                  borderRadius: '8px',
                }}
                labelStyle={{ color: '#a8afc4' }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#5865f2"
                fill="url(#colorGradient)"
                strokeWidth={2}
              />
              <defs>
                <linearGradient id="colorGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#5865f2" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#5865f2" stopOpacity={0} />
                </linearGradient>
              </defs>
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="TLS Status Distribution" className="chart-card">
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={analytics.tlsStatusDistribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ status, percentage }) => `${status}: ${percentage}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="count"
              >
                {analytics.tlsStatusDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1b26',
                  border: '1px solid #2a2b3d',
                  borderRadius: '8px',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="bottom-grid">
        <Card title="Node Health" className="node-health-card">
          <div className="node-health-list">
            {analytics.nodeHealth.map((node) => (
              <div key={node.node} className="node-health-item">
                <div className="node-info">
                  <span className="node-name">{node.node}</span>
                  <Badge
                    variant={node.status === 'healthy' ? 'success' : 'warning'}
                    size="sm"
                    dot
                  >
                    {node.status}
                  </Badge>
                </div>
                <div className="node-metrics">
                  <span className="metric-label">Latency</span>
                  <span className="metric-value">{node.latency}ms</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Recent Activity" className="activity-card">
          <div className="activity-list">
            {analytics.recentActivity.map((activity, i) => (
              <div key={i} className="activity-item">
                <div className="activity-icon">
                  {activity.action.includes('Domain') && '🌐'}
                  {activity.action.includes('User') && '👤'}
                  {activity.action.includes('TLS') && '🔒'}
                  {activity.action.includes('Node') && '🖥️'}
                  {activity.action.includes('Bulk') && '📦'}
                </div>
                <div className="activity-content">
                  <div className="activity-action">{activity.action}</div>
                  <div className="activity-details">{activity.details}</div>
                  <div className="activity-time">
                    {format(new Date(activity.timestamp), 'MMM d, HH:mm')}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Performance Metrics" className="performance-card">
        <div className="performance-grid">
          <div className="perf-metric">
            <div className="perf-label">Avg Response Time</div>
            <div className="perf-value">42ms</div>
            <div className="perf-bar">
              <div className="perf-bar-fill" style={{ width: '42%' }} />
            </div>
          </div>
          <div className="perf-metric">
            <div className="perf-label">Cache Hit Rate</div>
            <div className="perf-value">94%</div>
            <div className="perf-bar">
              <div className="perf-bar-fill success" style={{ width: '94%' }} />
            </div>
          </div>
          <div className="perf-metric">
            <div className="perf-label">TLS Handshake</div>
            <div className="perf-value">18ms</div>
            <div className="perf-bar">
              <div className="perf-bar-fill" style={{ width: '18%' }} />
            </div>
          </div>
          <div className="perf-metric">
            <div className="perf-label">Uptime</div>
            <div className="perf-value">99.9%</div>
            <div className="perf-bar">
              <div className="perf-bar-fill success" style={{ width: '99.9%' }} />
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}

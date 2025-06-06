/* VulnScope - 仪表板页面脚本 */

if (typeof Dashboard === 'undefined') {
    window.Dashboard = class Dashboard {
    constructor() {
        console.log('Dashboard constructor called');
        
        this.stats = {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            activeCollectors: 0,
            totalGrowth: 0,
            highGrowth: 0
        };
        this.collectors = [];
        this.recentVulns = [];
        this.charts = {};
        this.isRefreshing = false;
        
        this.init();
    }

    async init() {
        console.log('Dashboard init started');
        
        // 绑定事件
        this.bindEvents();
        
        // 加载数据
        await this.loadDashboardData();
        
        // 初始化图表（在数据加载完成后）
        this.initCharts();
        
        // 启动定时刷新
        this.startAutoRefresh();
        
        // 开启动画
        this.animateCounters();
        
        console.log('Dashboard init completed');
    }

    bindEvents() {
        // 刷新按钮
        const refreshBtn = document.querySelector('#refresh-data');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshData());
        }

        // 时间段切换
        document.querySelectorAll('.period-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchPeriod(btn.dataset.period);
            });
        });

        // 收集器控制
        document.querySelectorAll('.collector-control').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleCollector(btn.dataset.collector, btn.dataset.action);
            });
        });
    }

    async loadDashboardData() {
        try {
            console.log('Loading dashboard data...');
            // 显示加载状态
            this.showLoading();

            // 并行请求所有数据
            console.log('Making API requests...');
            const [statsData, collectorsData, vulnsData] = await Promise.all([
                VulnScope.API.stats.overview(),
                VulnScope.API.stats.collectors(),
                VulnScope.API.vulnerabilities.list({ limit: 10 })
            ]);

            console.log('API responses:', { statsData, collectorsData, vulnsData });

            // 更新统计数据
            if (statsData && statsData.success) {
                console.log('Updating stats with:', statsData.data);
                this.updateStats(statsData.data);
            } else {
                console.warn('Stats data not available:', statsData);
            }

            // 更新收集器状态
            if (collectorsData && collectorsData.success) {
                // 确保collectors_status是数组
                this.collectors = (collectorsData.data && collectorsData.data.collectors_status) || [];
                console.log('Updating collectors with:', this.collectors);
                this.updateCollectorStatus();
            } else {
                console.warn('Collectors data not available:', collectorsData);
            }

            // 更新最新漏洞
            if (vulnsData && vulnsData.success) {
                this.recentVulns = vulnsData.data || [];
                console.log('Updating vulnerabilities with:', this.recentVulns);
                this.updateRecentVulnerabilities();
            } else {
                console.warn('Vulnerabilities data not available:', vulnsData);
            }

            console.log('Dashboard data loaded successfully');

        } catch (error) {
            console.error('加载仪表板数据失败:', error);
            VulnScope.Notification.error('数据加载失败，请检查网络连接');
        } finally {
            this.hideLoading();
        }
    }

    updateStats(data) {
        const newStats = {
            total: data.total_vulnerabilities || 0,
            critical: data.critical_count || 0,
            high: data.high_count || 0,
            medium: data.medium_count || 0,
            low: data.low_count || 0,
            activeCollectors: this.collectors.filter(c => c.status === 'online').length || 6,
            totalGrowth: data.total_growth || Math.floor(Math.random() * 20) + 5,
            highGrowth: data.high_growth || Math.floor(Math.random() * 15) + 2
        };

        // 数字动画
        Object.keys(newStats).forEach(key => {
            if (key.includes('Growth')) return;
            this.animateNumber(key, this.stats[key], newStats[key]);
        });

        this.stats = newStats;
        this.updateStatsDisplay();
    }

    updateStatsDisplay() {
        // 更新统计卡片
        this.updateElement('#total-count', this.stats.total);
        this.updateElement('#critical-count', this.stats.critical);
        this.updateElement('#high-count', this.stats.high);
        this.updateElement('#medium-count', this.stats.medium);
        this.updateElement('#low-count', this.stats.low);
        this.updateElement('#active-collectors', this.stats.activeCollectors);
        
        // 更新增长率
        this.updateElement('#total-growth', `${this.stats.totalGrowth}%`);
        this.updateElement('#high-growth', `${this.stats.highGrowth}%`);
    }

    updateElement(selector, value) {
        const element = document.querySelector(selector);
        if (element) {
            element.textContent = value;
        }
    }

    animateNumber(key, from, to, duration = 1000) {
        const start = Date.now();
        const update = () => {
            const progress = Math.min((Date.now() - start) / duration, 1);
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(from + (to - from) * easeOut);
            
            const element = document.querySelector(`#${key.replace(/([A-Z])/g, '-$1').toLowerCase()}-count`);
            if (element) {
                element.textContent = current;
            }

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        };
        requestAnimationFrame(update);
    }

    animateCounters() {
        const counters = document.querySelectorAll('.counter');
        counters.forEach((counter, index) => {
            counter.style.fontVariantNumeric = 'tabular-nums';
            counter.style.animationDelay = `${index * 100}ms`;
            counter.classList.add('animate-fade-in');
        });
    }

    updateCollectorStatus() {
        const container = document.querySelector('#collectors-status');
        if (!container) return;

        // 确保collectors是数组
        if (!Array.isArray(this.collectors) || this.collectors.length === 0) {
            container.innerHTML = this.getEmptyState('暂无收集器数据');
            return;
        }

        const html = this.collectors.map(collector => `
            <div class="flex items-center justify-between p-3 rounded-lg border border-gray-100 hover:bg-gray-50 transition-all duration-200">
                <div class="flex items-center space-x-3">
                    <div class="status-indicator ${this.getStatusClass(collector.status)}"></div>
                    <div>
                        <p class="text-sm font-medium text-gray-900">${collector.name}</p>
                        <p class="text-xs text-gray-500">${VulnScope.Utils.timeAgo(collector.last_update)}</p>
                    </div>
                </div>
                <div class="text-right">
                    <p class="text-sm font-medium text-gray-900">${collector.count || 0}</p>
                    <p class="text-xs text-gray-500">条漏洞</p>
                </div>
                <div class="flex space-x-1">
                    <button class="btn btn-sm btn-outline collector-control" 
                            data-collector="${collector.name}" 
                            data-action="${collector.status === 'online' ? 'stop' : 'start'}"
                            title="${collector.status === 'online' ? '停止' : '启动'}">
                        <i class="fas ${collector.status === 'online' ? 'fa-stop' : 'fa-play'}"></i>
                    </button>
                    <button class="btn btn-sm btn-outline" 
                            onclick="dashboard.showCollectorLogs('${collector.name}')"
                            title="查看日志">
                        <i class="fas fa-file-alt"></i>
                    </button>
                </div>
            </div>
        `).join('');

        container.innerHTML = html;
    }

    updateRecentVulnerabilities() {
        const container = document.querySelector('#recent-vulnerabilities');
        if (!container) return;

        if (this.recentVulns.length === 0) {
            container.innerHTML = this.getEmptyState('暂无最新漏洞数据');
            return;
        }

        const html = this.recentVulns.slice(0, 8).map(vuln => `
            <div class="flex items-start space-x-3 p-3 rounded-lg border border-gray-100 hover:bg-gray-50 transition-all duration-200 cursor-pointer"
                 onclick="window.location.href='/vulnerabilities/${vuln.id}'">
                <div class="flex-shrink-0">
                    <div class="w-3 h-3 rounded-full ${this.getSeverityDot(vuln.severity)}"></div>
                </div>
                <div class="flex-grow min-w-0">
                    <p class="text-sm font-medium text-gray-900 truncate">${vuln.title}</p>
                    <p class="text-xs text-gray-500">${vuln.source}</p>
                    <div class="flex items-center space-x-2 mt-1">
                        <span class="severity-badge ${VulnScope.Utils.getSeverityClass(vuln.severity)}">
                            ${VulnScope.Utils.getSeverityText(vuln.severity)}
                        </span>
                        <span class="text-xs text-gray-500">${VulnScope.Utils.timeAgo(vuln.published_date)}</span>
                        ${vuln.cve_id ? `<span class="text-xs text-blue-600">${vuln.cve_id}</span>` : ''}
                    </div>
                </div>
            </div>
        `).join('');

        container.innerHTML = html;
    }

    initCharts() {
        console.log('Initializing charts...');
        
        // 简单的图表初始化
        setTimeout(() => {
            this.initSeverityChart();
            this.initTrendChart();
            this.initSourceChart();
            
            // 图表初始化完成后更新数据
            this.updateCharts();
        }, 100);
    }

    destroyAllCharts() {
        console.log('Destroying all charts...');
        
        // 销毁特定的canvas上的图表
        const canvasIds = ['severityChart', 'trendChart', 'sourceChart'];
        canvasIds.forEach(canvasId => {
            const canvas = document.getElementById(canvasId);
            if (canvas) {
                const existingChart = Chart.getChart(canvas);
                if (existingChart) {
                    try {
                        existingChart.destroy();
                        console.log(`Destroyed chart on ${canvasId}`);
                    } catch (error) {
                        console.warn(`Failed to destroy chart on ${canvasId}:`, error);
                    }
                }
                // 清洁canvas
                canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
            }
        });
        
        // 清空我们的图表引用
        this.charts = {};
    }

    initSeverityChart() {
        const ctx = document.getElementById('severityChart');
        if (!ctx) {
            console.warn('severityChart canvas not found');
            return;
        }

        console.log('Creating severity chart...');

        // 使用现代Chart.js方法销毁现有图表
        const existingChart = Chart.getChart(ctx);
        if (existingChart) {
            console.log('Destroying existing chart with ID:', existingChart.id);
            existingChart.destroy();
        }

        // 确保canvas清洁
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['严重', '高危', '中危', '低危'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'var(--critical-color)',
                        'var(--high-color)',
                        'var(--medium-color)',
                        'var(--low-color)'
                    ],
                    borderWidth: 0,
                    cutout: '65%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            usePointStyle: true,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                                return `${context.label}: ${context.parsed} (${percentage}%)`;
                            }
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    duration: 1500,
                    easing: 'easeInOutQuart'
                }
            }
        });
    }

    initTrendChart() {
        const ctx = document.getElementById('trendChart');
        if (!ctx) {
            console.warn('trendChart canvas not found');
            return;
        }

        console.log('Creating trend chart...');

        // 使用现代Chart.js方法销毁现有图表
        const existingChart = Chart.getChart(ctx);
        if (existingChart) {
            console.log('Destroying existing trend chart with ID:', existingChart.id);
            existingChart.destroy();
        }

        // 确保canvas清洁
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);

        this.charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['6天前', '5天前', '4天前', '3天前', '2天前', '昨天', '今天'],
                datasets: [{
                    label: '严重',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: 'var(--critical-color)',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }, {
                    label: '高危',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: 'var(--high-color)',
                    backgroundColor: 'rgba(234, 88, 12, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: 'white',
                        bodyColor: 'white',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        },
                        ticks: {
                            font: {
                                size: 11
                            }
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            }
                        }
                    }
                },
                animation: {
                    duration: 1500,
                    easing: 'easeInOutQuart'
                }
            }
        });
    }

    initSourceChart() {
        const ctx = document.getElementById('sourceChart');
        if (!ctx) {
            console.warn('sourceChart canvas not found');
            return;
        }

        console.log('Creating source chart...');

        // 使用现代Chart.js方法销毁现有图表
        const existingChart = Chart.getChart(ctx);
        if (existingChart) {
            console.log('Destroying existing source chart with ID:', existingChart.id);
            existingChart.destroy();
        }

        // 确保canvas清洁
        ctx.getContext('2d').clearRect(0, 0, ctx.width, ctx.height);

        this.charts.source = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['NVD', 'Exploit-DB', 'CVE Details', '长亭漏洞库', 'Aliyun AVD', 'Qianxin TI'],
                datasets: [{
                    label: '漏洞数量',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#3b82f6',
                        '#10b981',
                        '#f59e0b',
                        '#ef4444',
                        '#8b5cf6',
                        '#06b6d4'
                    ],
                    borderRadius: 4,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                animation: {
                    duration: 1500,
                    easing: 'easeInOutQuart'
                }
            }
        });
    }

    updateCharts() {
        // 更新严重程度分布图
        if (this.charts.severity) {
            this.charts.severity.data.datasets[0].data = [
                this.stats.critical,
                this.stats.high,
                this.stats.medium,
                this.stats.low
            ];
            this.charts.severity.update('active');
        }

        // 更新趋势图（模拟数据）
        if (this.charts.trend) {
            this.charts.trend.data.datasets[0].data = this.generateTrendData(this.stats.critical);
            this.charts.trend.data.datasets[1].data = this.generateTrendData(this.stats.high);
            this.charts.trend.update('active');
        }

        // 更新来源分布图
        if (this.charts.source) {
            const sourceData = this.calculateSourceDistribution();
            this.charts.source.data.datasets[0].data = sourceData;
            this.charts.source.update('active');
        }
    }

    generateTrendData(current) {
        const data = [];
        let value = current;
        for (let i = 6; i >= 0; i--) {
            const variance = Math.floor(Math.random() * 10) - 5;
            value = Math.max(0, value + variance);
            data.unshift(value);
        }
        data[data.length - 1] = current; // 确保最后一个是当前值
        return data;
    }

    calculateSourceDistribution() {
        // 模拟来源分布数据
        const sources = ['NVD', 'Exploit-DB', 'CVE Details', '长亭漏洞库', 'Aliyun AVD', 'Qianxin TI'];
        return sources.map(() => Math.floor(Math.random() * 50) + 10);
    }

    async refreshData() {
        if (this.isRefreshing) return;
        
        this.isRefreshing = true;
        const refreshBtn = document.querySelector('#refresh-data');
        if (refreshBtn) {
            refreshBtn.classList.add('animate-spin');
        }

        try {
            await this.loadDashboardData();
            VulnScope.Notification.success('数据已更新');
        } catch (error) {
            VulnScope.Notification.error('数据更新失败');
        } finally {
            this.isRefreshing = false;
            if (refreshBtn) {
                refreshBtn.classList.remove('animate-spin');
            }
        }
    }

    switchPeriod(period) {
        // 更新按钮状态
        document.querySelectorAll('.period-btn').forEach(btn => {
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-secondary');
        });
        
        const activeBtn = document.querySelector(`[data-period="${period}"]`);
        if (activeBtn) {
            activeBtn.classList.remove('btn-secondary');
            activeBtn.classList.add('btn-primary');
        }

        // 重新加载对应时间段的数据
        this.loadPeriodData(period);
    }

    async loadPeriodData(period) {
        try {
            const data = await VulnScope.API.stats.trends(period);
            if (data && data.success) {
                // 更新图表数据
                this.updateChartsWithPeriodData(data.data);
            }
        } catch (error) {
            console.error('加载时间段数据失败:', error);
        }
    }

    updateChartsWithPeriodData(data) {
        // 更新趋势图
        if (this.charts.trend && data.trend) {
            this.charts.trend.data.labels = data.trend.labels;
            this.charts.trend.data.datasets[0].data = data.trend.critical;
            this.charts.trend.data.datasets[1].data = data.trend.high;
            this.charts.trend.update('active');
        }
    }

    async toggleCollector(name, action) {
        try {
            if (action === 'start') {
                await VulnScope.API.collectors.start(name);
                VulnScope.Notification.success(`收集器 ${name} 已启动`);
            } else {
                await VulnScope.API.collectors.stop(name);
                VulnScope.Notification.success(`收集器 ${name} 已停止`);
            }
            
            // 刷新收集器状态
            const collectorsData = await VulnScope.API.stats.collectors();
            if (collectorsData && collectorsData.success) {
                this.collectors = collectorsData.data || [];
                this.updateCollectorStatus();
            }
        } catch (error) {
            VulnScope.Notification.error(`操作失败: ${error.message}`);
        }
    }

    async showCollectorLogs(name) {
        try {
            const logs = await VulnScope.API.collectors.logs(name);
            if (logs && logs.success) {
                this.openLogsModal(name, logs.data);
            }
        } catch (error) {
            VulnScope.Notification.error(`获取日志失败: ${error.message}`);
        }
    }

    openLogsModal(name, logs) {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.innerHTML = `
            <div class="bg-white rounded-lg max-w-4xl max-h-96 overflow-hidden">
                <div class="flex items-center justify-between p-4 border-b">
                    <h3 class="text-lg font-semibold">${name} 收集器日志</h3>
                    <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="p-4 max-h-80 overflow-y-auto custom-scrollbar">
                    <pre class="text-sm text-gray-800 whitespace-pre-wrap">${logs || '暂无日志'}</pre>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    startAutoRefresh() {
        // 每30秒自动刷新数据
        setInterval(() => {
            if (!this.isRefreshing) {
                this.loadDashboardData();
            }
        }, VulnScope.Config.REFRESH_INTERVAL);
    }

    showLoading() {
        const elements = [
            '#stats-cards',
            '#collectors-status',
            '#recent-vulnerabilities'
        ];
        
        elements.forEach(selector => {
            VulnScope.Loading.show(selector, '加载中...');
        });
    }

    hideLoading() {
        const elements = [
            '#stats-cards',
            '#collectors-status', 
            '#recent-vulnerabilities'
        ];
        
        elements.forEach(selector => {
            VulnScope.Loading.hide(selector);
        });
    }

    getStatusClass(status) {
        const map = {
            'online': 'status-online',
            'warning': 'status-warning',
            'offline': 'status-offline'
        };
        return map[status] || 'status-offline';
    }

    getSeverityDot(severity) {
        const map = {
            'critical': 'bg-red-500',
            'high': 'bg-orange-500',
            'medium': 'bg-yellow-500',
            'low': 'bg-green-500'
        };
        return map[severity] || 'bg-gray-500';
    }

    getEmptyState(message) {
        return `
            <div class="text-center py-8 text-gray-500">
                <i class="fas fa-inbox text-3xl mb-3"></i>
                <p>${message}</p>
            </div>
        `;
    }
    }
}

// 页面加载完成后初始化仪表板
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, checking for dashboard...');
    
    // 检查页面是否为dashboard页面
    const isDashboardPage = window.location.pathname === '/' || 
                           document.querySelector('.stats-grid') || 
                           document.getElementById('severityChart');
                           
    console.log('Is dashboard page:', isDashboardPage);
    
    if (isDashboardPage) {
        // 在初始化新Dashboard前清理所有现有的Chart实例
        const canvasIds = ['severityChart', 'trendChart', 'sourceChart'];
        canvasIds.forEach(canvasId => {
            const canvas = document.getElementById(canvasId);
            if (canvas) {
                const existingChart = Chart.getChart(canvas);
                if (existingChart) {
                    console.log(`Cleaning up existing chart on ${canvasId} before initialization`);
                    existingChart.destroy();
                }
            }
        });
        
        console.log('Initializing Dashboard...');
        window.dashboard = new Dashboard();
    }
}); 

// 页面卸载时清理资源
window.addEventListener('beforeunload', function() {
    if (window.dashboard && window.dashboard.destroyAllCharts) {
        console.log('Cleaning up dashboard resources...');
        window.dashboard.destroyAllCharts();
    }
});

// 页面隐藏时也清理（处理SPA导航）
document.addEventListener('visibilitychange', function() {
    if (document.hidden && window.dashboard && window.dashboard.destroyAllCharts) {
        console.log('Page hidden, cleaning up charts...');
        window.dashboard.destroyAllCharts();
    }
});
/* VulnScope - 搜索页面脚本 */

class SearchPage {
    constructor() {
        this.currentQuery = '';
        this.currentFilters = {};
        this.currentPage = 1;
        this.pageSize = 20;
        this.totalResults = 0;
        this.results = [];
        this.pagination = null;
        this.isLoading = false;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.initFilters();
        this.loadUrlParams();
        this.initPagination();
        
        // 如果有初始查询，执行搜索
        if (this.currentQuery) {
            this.performSearch();
        }
    }

    bindEvents() {
        // 搜索表单
        const searchForm = document.getElementById('search-form');
        if (searchForm) {
            searchForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleSearch();
            });
        }

        // 搜索输入框
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            // 实时搜索（防抖）
            const debouncedSearch = VulnScope.Utils.debounce(() => {
                if (searchInput.value.trim() !== this.currentQuery) {
                    this.handleSearch();
                }
            }, 500);
            
            searchInput.addEventListener('input', debouncedSearch);
            
            // 快捷键支持
            searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    this.clearSearch();
                }
            });
        }

        // 高级搜索切换
        const advancedToggle = document.getElementById('advanced-toggle');
        if (advancedToggle) {
            advancedToggle.addEventListener('click', () => {
                this.toggleAdvancedSearch();
            });
        }

        // 过滤器
        document.querySelectorAll('.filter-option').forEach(option => {
            option.addEventListener('click', () => {
                this.toggleFilter(option);
            });
        });

        document.querySelectorAll('.filter-select').forEach(select => {
            select.addEventListener('change', () => {
                this.applyFilters();
            });
        });

        // 排序选择
        const sortSelect = document.getElementById('sort-select');
        if (sortSelect) {
            sortSelect.addEventListener('change', () => {
                this.handleSortChange();
            });
        }

        // 导出按钮
        const exportBtn = document.getElementById('export-results');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportResults();
            });
        }

        // 清除过滤器
        const clearFiltersBtn = document.getElementById('clear-filters');
        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', () => {
                this.clearFilters();
            });
        }
    }

    initFilters() {
        // 严重程度过滤器
        this.severityFilters = ['critical', 'high', 'medium', 'low'];
        
        // 来源过滤器
        this.sourceFilters = ['NVD', 'Exploit-DB', 'CVE Details', '长亭漏洞库', 'Aliyun AVD', 'Qianxin TI'];
        
        // 时间范围过滤器
        this.timeRanges = {
            'today': '今天',
            'week': '本周',
            'month': '本月',
            'quarter': '本季度',
            'year': '今年'
        };
    }

    loadUrlParams() {
        const params = VulnScope.Utils.getUrlParams();
        
        // 搜索查询
        if (params.q) {
            this.currentQuery = params.q;
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.value = this.currentQuery;
            }
        }

        // 页码
        if (params.page) {
            this.currentPage = parseInt(params.page) || 1;
        }

        // 页面大小
        if (params.size) {
            this.pageSize = parseInt(params.size) || 20;
        }

        // 过滤器
        Object.keys(params).forEach(key => {
            if (!['q', 'page', 'size'].includes(key)) {
                this.currentFilters[key] = params[key];
            }
        });

        this.updateFilterUI();
    }

    updateUrl() {
        const params = new URLSearchParams();
        
        if (this.currentQuery) {
            params.set('q', this.currentQuery);
        }
        
        if (this.currentPage > 1) {
            params.set('page', this.currentPage);
        }
        
        if (this.pageSize !== 20) {
            params.set('size', this.pageSize);
        }
        
        Object.keys(this.currentFilters).forEach(key => {
            if (this.currentFilters[key]) {
                params.set(key, this.currentFilters[key]);
            }
        });

        const newUrl = `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`;
        window.history.pushState({}, '', newUrl);
    }

    async handleSearch() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            this.currentQuery = searchInput.value.trim();
        }
        
        this.currentPage = 1; // 重置到第一页
        await this.performSearch();
    }

    async performSearch() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        this.showLoading();
        
        try {
            const searchParams = {
                q: this.currentQuery,
                page: this.currentPage,
                limit: this.pageSize,
                ...this.currentFilters
            };

            const response = await VulnScope.API.vulnerabilities.search(this.currentQuery, searchParams);
            
            if (response && response.success) {
                this.results = response.data.results || [];
                this.totalResults = response.data.total || 0;
                
                this.renderResults();
                this.updatePagination();
                this.updateResultsInfo();
                this.updateUrl();
            } else {
                throw new Error('搜索请求失败');
            }
            
        } catch (error) {
            console.error('搜索失败:', error);
            VulnScope.Notification.error('搜索失败，请稍后重试');
            this.renderError(error.message);
        } finally {
            this.isLoading = false;
            this.hideLoading();
        }
    }

    renderResults() {
        const resultsContainer = document.getElementById('search-results');
        if (!resultsContainer) return;

        if (this.results.length === 0) {
            resultsContainer.innerHTML = this.renderEmptyState();
            return;
        }

        const html = this.results.map(result => this.renderResultItem(result)).join('');
        resultsContainer.innerHTML = html;

        // 添加结果项动画
        document.querySelectorAll('.result-item').forEach((item, index) => {
            item.style.animationDelay = `${index * 50}ms`;
            item.classList.add('animate-fade-in');
        });
    }

    renderResultItem(result) {
        const severityClass = VulnScope.Utils.getSeverityClass(result.severity);
        const severityText = VulnScope.Utils.getSeverityText(result.severity);
        const publishedDate = VulnScope.Utils.formatDate(result.published_date, 'YYYY-MM-DD');
        const timeAgo = VulnScope.Utils.timeAgo(result.published_date);

        return `
            <div class="result-item card card-hover cursor-pointer" onclick="this.viewDetails('${result.id}')">
                <div class="card-body">
                    <div class="flex items-start justify-between">
                        <div class="flex-grow">
                            <div class="flex items-center space-x-3 mb-2">
                                <h3 class="text-lg font-semibold text-gray-900 hover:text-indigo-600 transition-colors">
                                    ${this.highlightText(result.title, this.currentQuery)}
                                </h3>
                                <span class="severity-badge ${severityClass}">${severityText}</span>
                                ${result.cve_id ? `<span class="text-sm text-blue-600 font-mono">${result.cve_id}</span>` : ''}
                            </div>
                            
                            <p class="text-gray-600 mb-3 line-clamp-2">
                                ${this.highlightText(result.description || '', this.currentQuery)}
                            </p>
                            
                            <div class="flex items-center space-x-4 text-sm text-gray-500">
                                <span class="flex items-center">
                                    <i class="fas fa-source mr-1"></i>
                                    ${result.source}
                                </span>
                                <span class="flex items-center">
                                    <i class="fas fa-calendar mr-1"></i>
                                    ${publishedDate}
                                </span>
                                <span class="flex items-center">
                                    <i class="fas fa-clock mr-1"></i>
                                    ${timeAgo}
                                </span>
                                ${result.exploits_count > 0 ? `
                                <span class="flex items-center text-red-600">
                                    <i class="fas fa-bomb mr-1"></i>
                                    ${result.exploits_count} 个利用
                                </span>
                                ` : ''}
                            </div>
                        </div>
                        
                        <div class="flex flex-col items-end space-y-2">
                            <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); this.copyToClipboard('${result.cve_id || result.id}')">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); this.shareResult('${result.id}')">
                                <i class="fas fa-share"></i>
                            </button>
                        </div>
                    </div>
                    
                    ${result.tags && result.tags.length > 0 ? `
                    <div class="mt-3 flex flex-wrap gap-1">
                        ${result.tags.slice(0, 5).map(tag => `
                            <span class="inline-flex items-center px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded-md">
                                ${tag}
                            </span>
                        `).join('')}
                        ${result.tags.length > 5 ? `<span class="text-xs text-gray-500">+${result.tags.length - 5} 更多</span>` : ''}
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    renderEmptyState() {
        if (this.currentQuery) {
            return `
                <div class="text-center py-12">
                    <i class="fas fa-search text-4xl text-gray-300 mb-4"></i>
                    <h3 class="text-lg font-medium text-gray-900 mb-2">未找到相关结果</h3>
                    <p class="text-gray-500 mb-4">尝试使用不同的关键词或调整搜索条件</p>
                    <div class="flex justify-center space-x-3">
                        <button onclick="searchPage.clearSearch()" class="btn btn-outline">
                            <i class="fas fa-times mr-2"></i>清除搜索
                        </button>
                        <button onclick="searchPage.showSearchTips()" class="btn btn-primary">
                            <i class="fas fa-lightbulb mr-2"></i>搜索技巧
                        </button>
                    </div>
                </div>
            `;
        } else {
            return `
                <div class="text-center py-12">
                    <i class="fas fa-search text-4xl text-gray-300 mb-4"></i>
                    <h3 class="text-lg font-medium text-gray-900 mb-2">开始搜索漏洞情报</h3>
                    <p class="text-gray-500 mb-4">输入漏洞名称、CVE编号或关键词</p>
                    <div class="max-w-md mx-auto">
                        <div class="flex space-x-2">
                            <button onclick="searchPage.quickSearch('CVE-2024')" class="btn btn-sm btn-outline">CVE-2024</button>
                            <button onclick="searchPage.quickSearch('RCE')" class="btn btn-sm btn-outline">远程代码执行</button>
                            <button onclick="searchPage.quickSearch('SQL injection')" class="btn btn-sm btn-outline">SQL注入</button>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    renderError(message) {
        const resultsContainer = document.getElementById('search-results');
        if (!resultsContainer) return;

        resultsContainer.innerHTML = `
            <div class="text-center py-12">
                <i class="fas fa-exclamation-triangle text-4xl text-red-300 mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">搜索出错</h3>
                <p class="text-gray-500 mb-4">${message}</p>
                <button onclick="searchPage.performSearch()" class="btn btn-primary">
                    <i class="fas fa-redo mr-2"></i>重新搜索
                </button>
            </div>
        `;
    }

    highlightText(text, query) {
        if (!query || !text) return text;
        
        const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return text.replace(regex, '<mark class="bg-yellow-200 text-yellow-800">$1</mark>');
    }

    updateResultsInfo() {
        const resultsInfo = document.getElementById('results-info');
        if (!resultsInfo) return;

        const start = (this.currentPage - 1) * this.pageSize + 1;
        const end = Math.min(this.currentPage * this.pageSize, this.totalResults);

        resultsInfo.innerHTML = `
            显示第 <span class="font-semibold">${start}</span> - <span class="font-semibold">${end}</span> 条结果，
            共 <span class="font-semibold">${this.totalResults.toLocaleString()}</span> 条
            ${this.currentQuery ? `关于 "<span class="font-semibold text-indigo-600">${this.currentQuery}</span>" 的搜索结果` : ''}
        `;
    }

    initPagination() {
        const paginationContainer = document.getElementById('pagination-container');
        if (!paginationContainer) return;

        this.pagination = new VulnScope.Pagination(paginationContainer, {
            page: this.currentPage,
            limit: this.pageSize,
            total: this.totalResults,
            onChange: (page) => {
                this.currentPage = page;
                this.performSearch();
                this.scrollToTop();
            }
        });
    }

    updatePagination() {
        if (this.pagination) {
            this.pagination.update({
                page: this.currentPage,
                total: this.totalResults
            });
        }
    }

    toggleAdvancedSearch() {
        const advancedPanel = document.getElementById('advanced-search');
        const toggle = document.getElementById('advanced-toggle');
        
        if (advancedPanel && toggle) {
            const isVisible = !advancedPanel.classList.contains('hidden');
            
            if (isVisible) {
                advancedPanel.classList.add('hidden');
                toggle.innerHTML = '<i class="fas fa-chevron-down mr-2"></i>高级搜索';
            } else {
                advancedPanel.classList.remove('hidden');
                toggle.innerHTML = '<i class="fas fa-chevron-up mr-2"></i>收起高级搜索';
            }
        }
    }

    toggleFilter(element) {
        element.classList.toggle('active');
        this.applyFilters();
    }

    applyFilters() {
        // 收集所有激活的过滤器
        const filters = {};

        // 严重程度过滤器
        const activeSeverities = [];
        document.querySelectorAll('.severity-filter.active').forEach(el => {
            activeSeverities.push(el.dataset.value);
        });
        if (activeSeverities.length > 0) {
            filters.severity = activeSeverities.join(',');
        }

        // 来源过滤器
        const activeSources = [];
        document.querySelectorAll('.source-filter.active').forEach(el => {
            activeSources.push(el.dataset.value);
        });
        if (activeSources.length > 0) {
            filters.source = activeSources.join(',');
        }

        // 时间范围过滤器
        const timeRange = document.getElementById('time-range-select')?.value;
        if (timeRange) {
            filters.time_range = timeRange;
        }

        // 是否有利用代码
        const hasExploit = document.getElementById('has-exploit-check')?.checked;
        if (hasExploit) {
            filters.has_exploit = 'true';
        }

        // 分数范围
        const minScore = document.getElementById('min-score-input')?.value;
        const maxScore = document.getElementById('max-score-input')?.value;
        if (minScore) {
            filters.min_score = minScore;
        }
        if (maxScore) {
            filters.max_score = maxScore;
        }

        this.currentFilters = filters;
        this.currentPage = 1; // 重置分页
        this.performSearch();
    }

    clearFilters() {
        this.currentFilters = {};
        
        // 清除UI状态
        document.querySelectorAll('.filter-option.active').forEach(el => {
            el.classList.remove('active');
        });
        
        document.querySelectorAll('.filter-select').forEach(select => {
            select.value = '';
        });

        document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = false;
        });

        this.performSearch();
    }

    clearSearch() {
        this.currentQuery = '';
        this.currentFilters = {};
        this.currentPage = 1;
        
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.value = '';
            searchInput.focus();
        }
        
        this.clearFilters();
    }

    updateFilterUI() {
        // 更新严重程度过滤器UI
        if (this.currentFilters.severity) {
            const severities = this.currentFilters.severity.split(',');
            severities.forEach(severity => {
                const element = document.querySelector(`.severity-filter[data-value="${severity}"]`);
                if (element) {
                    element.classList.add('active');
                }
            });
        }

        // 更新来源过滤器UI
        if (this.currentFilters.source) {
            const sources = this.currentFilters.source.split(',');
            sources.forEach(source => {
                const element = document.querySelector(`.source-filter[data-value="${source}"]`);
                if (element) {
                    element.classList.add('active');
                }
            });
        }

        // 更新其他过滤器
        Object.keys(this.currentFilters).forEach(key => {
            const element = document.getElementById(`${key.replace('_', '-')}-select`) || 
                          document.getElementById(`${key.replace('_', '-')}-input`) ||
                          document.getElementById(`${key.replace('_', '-')}-check`);
            
            if (element) {
                if (element.type === 'checkbox') {
                    element.checked = this.currentFilters[key] === 'true';
                } else {
                    element.value = this.currentFilters[key];
                }
            }
        });
    }

    handleSortChange() {
        const sortSelect = document.getElementById('sort-select');
        if (sortSelect) {
            this.currentFilters.sort = sortSelect.value;
            this.performSearch();
        }
    }

    quickSearch(query) {
        this.currentQuery = query;
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.value = query;
        }
        this.performSearch();
    }

    async exportResults() {
        try {
            const exportBtn = document.getElementById('export-results');
            if (exportBtn) {
                exportBtn.classList.add('loading');
                exportBtn.disabled = true;
            }

            const params = {
                q: this.currentQuery,
                ...this.currentFilters,
                format: 'csv'
            };

            const response = await VulnScope.API.vulnerabilities.export('csv', params);
            
            if (response && response.success) {
                // 创建下载链接
                const blob = new Blob([response.data], { type: 'text/csv' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `vulnerabilities_${new Date().toISOString().split('T')[0]}.csv`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                VulnScope.Notification.success('数据导出成功');
            } else {
                throw new Error('导出失败');
            }
        } catch (error) {
            console.error('导出失败:', error);
            VulnScope.Notification.error('数据导出失败');
        } finally {
            const exportBtn = document.getElementById('export-results');
            if (exportBtn) {
                exportBtn.classList.remove('loading');
                exportBtn.disabled = false;
            }
        }
    }

    viewDetails(id) {
        window.location.href = `/vulnerabilities/${id}`;
    }

    async copyToClipboard(text) {
        try {
            await VulnScope.Utils.copyToClipboard(text);
            VulnScope.Notification.success('已复制到剪贴板');
        } catch (error) {
            VulnScope.Notification.error('复制失败');
        }
    }

    shareResult(id) {
        const url = `${window.location.origin}/vulnerabilities/${id}`;
        this.copyToClipboard(url);
    }

    showSearchTips() {
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.innerHTML = `
            <div class="bg-white rounded-lg max-w-2xl max-h-96 overflow-hidden">
                <div class="flex items-center justify-between p-4 border-b">
                    <h3 class="text-lg font-semibold">搜索技巧</h3>
                    <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="p-4 max-h-80 overflow-y-auto">
                    <div class="space-y-4">
                        <div>
                            <h4 class="font-medium text-gray-900 mb-2">基础搜索</h4>
                            <ul class="text-sm text-gray-600 space-y-1">
                                <li>• 输入关键词进行全文搜索</li>
                                <li>• 支持中英文搜索</li>
                                <li>• 自动高亮匹配内容</li>
                            </ul>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900 mb-2">高级搜索</h4>
                            <ul class="text-sm text-gray-600 space-y-1">
                                <li>• 使用引号进行精确匹配："SQL injection"</li>
                                <li>• 使用 CVE- 前缀搜索特定漏洞：CVE-2024-1234</li>
                                <li>• 使用产品名称搜索：Apache, Windows, Linux</li>
                                <li>• 使用漏洞类型搜索：RCE, XSS, SQLi</li>
                            </ul>
                        </div>
                        <div>
                            <h4 class="font-medium text-gray-900 mb-2">过滤器</h4>
                            <ul class="text-sm text-gray-600 space-y-1">
                                <li>• 按严重程度筛选</li>
                                <li>• 按漏洞来源筛选</li>
                                <li>• 按发布时间筛选</li>
                                <li>• 按是否有利用代码筛选</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    scrollToTop() {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showLoading() {
        VulnScope.Loading.show('#search-results', '搜索中...');
    }

    hideLoading() {
        VulnScope.Loading.hide('#search-results');
    }
}

// 全局实例
let searchPage;

// 页面加载完成后初始化搜索页面
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('search-page')) {
        searchPage = new SearchPage();
    }
}); 
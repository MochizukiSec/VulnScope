/* VulnScope - 漏洞管理页面脚本 */

class VulnerabilitiesPage {
    constructor() {
        this.currentPage = 1;
        this.pageSize = 20;
        this.totalCount = 0;
        this.currentFilters = {};
        this.currentSort = { field: 'published_date', direction: 'desc' };
        this.vulnerabilities = [];
        this.pagination = null;
        this.isLoading = false;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadUrlParams();
        this.initPagination();
        this.loadVulnerabilities();
    }

    bindEvents() {
        // 过滤器事件
        document.querySelectorAll('.filter-select').forEach(select => {
            select.addEventListener('change', () => {
                this.applyFilters();
            });
        });

        // 搜索框
        const searchInput = document.getElementById('vuln-search');
        if (searchInput) {
            const debouncedSearch = VulnScope.Utils.debounce(() => {
                this.applyFilters();
            }, 500);
            searchInput.addEventListener('input', debouncedSearch);
        }

        // 批量操作
        const selectAllCheckbox = document.getElementById('select-all');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                this.selectAll(e.target.checked);
            });
        }

        // 批量删除
        const deleteSelectedBtn = document.getElementById('delete-selected');
        if (deleteSelectedBtn) {
            deleteSelectedBtn.addEventListener('click', () => {
                this.deleteSelected();
            });
        }

        // 导出按钮
        const exportBtn = document.getElementById('export-vulnerabilities');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportVulnerabilities();
            });
        }

        // 刷新按钮
        const refreshBtn = document.getElementById('refresh-vulnerabilities');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadVulnerabilities();
            });
        }
    }

    loadUrlParams() {
        const params = VulnScope.Utils.getUrlParams();
        
        if (params.page) {
            this.currentPage = parseInt(params.page) || 1;
        }
        
        if (params.size) {
            this.pageSize = parseInt(params.size) || 20;
        }

        if (params.sort) {
            const [field, direction] = params.sort.split('_');
            this.currentSort = { field, direction: direction || 'desc' };
        }

        // 过滤器参数
        ['severity', 'source', 'status', 'search'].forEach(key => {
            if (params[key]) {
                this.currentFilters[key] = params[key];
            }
        });

        this.updateFilterUI();
    }

    updateUrl() {
        const params = new URLSearchParams();
        
        if (this.currentPage > 1) {
            params.set('page', this.currentPage);
        }
        
        if (this.pageSize !== 20) {
            params.set('size', this.pageSize);
        }
        
        if (this.currentSort.field !== 'published_date' || this.currentSort.direction !== 'desc') {
            params.set('sort', `${this.currentSort.field}_${this.currentSort.direction}`);
        }
        
        Object.keys(this.currentFilters).forEach(key => {
            if (this.currentFilters[key]) {
                params.set(key, this.currentFilters[key]);
            }
        });

        const newUrl = `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`;
        window.history.pushState({}, '', newUrl);
    }

    async loadVulnerabilities() {
        if (this.isLoading) return;
        
        this.isLoading = true;
        this.showLoading();
        
        try {
            const params = {
                page: this.currentPage,
                limit: this.pageSize,
                sort: this.currentSort.field,
                order: this.currentSort.direction,
                ...this.currentFilters
            };

            const response = await VulnScope.API.vulnerabilities.list(params);
            
            if (response && response.success) {
                this.vulnerabilities = response.data.vulnerabilities || [];
                this.totalCount = response.data.total || 0;
                
                this.renderTable();
                this.updatePagination();
                this.updateResultsInfo();
                this.updateUrl();
            } else {
                throw new Error('获取数据失败');
            }
            
        } catch (error) {
            console.error('加载漏洞数据失败:', error);
            VulnScope.Notification.error('数据加载失败，请稍后重试');
            this.renderError();
        } finally {
            this.isLoading = false;
            this.hideLoading();
        }
    }

    renderTable() {
        const tbody = document.getElementById('vulnerabilities-tbody');
        if (!tbody) return;

        if (this.vulnerabilities.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-8 text-gray-500">
                        <i class="fas fa-inbox text-3xl mb-3"></i>
                        <p>暂无漏洞数据</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.vulnerabilities.map(vuln => this.renderTableRow(vuln)).join('');
        
        // 绑定表格行事件
        this.bindTableEvents();
    }

    renderTableRow(vuln) {
        const severityClass = VulnScope.Utils.getSeverityClass(vuln.severity);
        const severityText = VulnScope.Utils.getSeverityText(vuln.severity);
        const publishedDate = VulnScope.Utils.formatDate(vuln.published_date, 'YYYY-MM-DD');
        const timeAgo = VulnScope.Utils.timeAgo(vuln.published_date);

        return `
            <tr class="hover:bg-gray-50 transition-colors duration-200" data-id="${vuln.id}">
                <td class="px-4 py-3">
                    <input type="checkbox" class="vuln-checkbox" value="${vuln.id}" />
                </td>
                <td class="px-4 py-3">
                    <div class="flex items-start space-x-3">
                        <div class="flex-grow">
                            <h4 class="font-medium text-gray-900 hover:text-indigo-600 cursor-pointer truncate" 
                                onclick="window.location.href='/vulnerabilities/${vuln.id}'"
                                title="${vuln.title}">
                                ${vuln.title}
                            </h4>
                            ${vuln.cve_id ? `<p class="text-sm text-blue-600 font-mono">${vuln.cve_id}</p>` : ''}
                        </div>
                    </div>
                </td>
                <td class="px-4 py-3">
                    <span class="severity-badge ${severityClass}">${severityText}</span>
                </td>
                <td class="px-4 py-3">
                    <span class="text-sm text-gray-600">${vuln.source}</span>
                </td>
                <td class="px-4 py-3">
                    <div class="text-sm text-gray-900">${publishedDate}</div>
                    <div class="text-xs text-gray-500">${timeAgo}</div>
                </td>
                <td class="px-4 py-3">
                    ${vuln.cvss_score ? `
                        <div class="flex items-center">
                            <span class="text-sm font-medium">${vuln.cvss_score}</span>
                            <div class="ml-2 w-16 bg-gray-200 rounded-full h-2">
                                <div class="bg-gradient-to-r from-green-500 to-red-500 h-2 rounded-full" 
                                     style="width: ${(vuln.cvss_score / 10) * 100}%"></div>
                            </div>
                        </div>
                    ` : '<span class="text-gray-400">-</span>'}
                </td>
                <td class="px-4 py-3">
                    <div class="flex items-center space-x-1">
                        ${vuln.exploits_count > 0 ? `
                            <span class="inline-flex items-center px-2 py-1 text-xs bg-red-100 text-red-800 rounded-full">
                                <i class="fas fa-bomb mr-1"></i>${vuln.exploits_count}
                            </span>
                        ` : ''}
                        ${vuln.references_count > 0 ? `
                            <span class="inline-flex items-center px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
                                <i class="fas fa-link mr-1"></i>${vuln.references_count}
                            </span>
                        ` : ''}
                    </div>
                </td>
                <td class="px-4 py-3">
                    <div class="flex items-center space-x-2">
                        <button onclick="this.viewVulnerability('${vuln.id}')" 
                                class="btn btn-sm btn-outline" title="查看详情">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button onclick="this.editVulnerability('${vuln.id}')" 
                                class="btn btn-sm btn-outline" title="编辑">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button onclick="this.deleteVulnerability('${vuln.id}')" 
                                class="btn btn-sm btn-error" title="删除">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }

    bindTableEvents() {
        // 表格排序
        document.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                this.handleSort(th.dataset.sort);
            });
        });

        // 复选框事件
        document.querySelectorAll('.vuln-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.updateBatchActions();
            });
        });
    }

    handleSort(field) {
        if (this.currentSort.field === field) {
            this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.currentSort.field = field;
            this.currentSort.direction = 'desc';
        }
        
        this.currentPage = 1;
        this.loadVulnerabilities();
        this.updateSortUI();
    }

    updateSortUI() {
        // 清除所有排序图标
        document.querySelectorAll('th[data-sort]').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            const icon = th.querySelector('.sort-icon');
            if (icon) icon.remove();
        });

        // 添加当前排序图标
        const currentTh = document.querySelector(`th[data-sort="${this.currentSort.field}"]`);
        if (currentTh) {
            currentTh.classList.add(`sort-${this.currentSort.direction}`);
            const icon = document.createElement('i');
            icon.className = `fas fa-sort-${this.currentSort.direction === 'asc' ? 'up' : 'down'} ml-1 sort-icon`;
            currentTh.appendChild(icon);
        }
    }

    applyFilters() {
        const filters = {};
        
        // 搜索关键词
        const searchInput = document.getElementById('vuln-search');
        if (searchInput && searchInput.value.trim()) {
            filters.search = searchInput.value.trim();
        }

        // 严重程度过滤器
        const severitySelect = document.getElementById('severity-filter');
        if (severitySelect && severitySelect.value) {
            filters.severity = severitySelect.value;
        }

        // 来源过滤器
        const sourceSelect = document.getElementById('source-filter');
        if (sourceSelect && sourceSelect.value) {
            filters.source = sourceSelect.value;
        }

        // 状态过滤器
        const statusSelect = document.getElementById('status-filter');
        if (statusSelect && statusSelect.value) {
            filters.status = statusSelect.value;
        }

        this.currentFilters = filters;
        this.currentPage = 1;
        this.loadVulnerabilities();
    }

    updateFilterUI() {
        // 更新搜索框
        const searchInput = document.getElementById('vuln-search');
        if (searchInput && this.currentFilters.search) {
            searchInput.value = this.currentFilters.search;
        }

        // 更新下拉框
        ['severity', 'source', 'status'].forEach(filterType => {
            const select = document.getElementById(`${filterType}-filter`);
            if (select && this.currentFilters[filterType]) {
                select.value = this.currentFilters[filterType];
            }
        });
    }

    selectAll(checked) {
        document.querySelectorAll('.vuln-checkbox').forEach(checkbox => {
            checkbox.checked = checked;
        });
        this.updateBatchActions();
    }

    updateBatchActions() {
        const checkedBoxes = document.querySelectorAll('.vuln-checkbox:checked');
        const batchActions = document.getElementById('batch-actions');
        const deleteBtn = document.getElementById('delete-selected');
        
        if (batchActions) {
            batchActions.style.display = checkedBoxes.length > 0 ? 'block' : 'none';
        }
        
        if (deleteBtn) {
            deleteBtn.textContent = `删除选中 (${checkedBoxes.length})`;
        }
    }

    async deleteSelected() {
        const checkedBoxes = document.querySelectorAll('.vuln-checkbox:checked');
        const ids = Array.from(checkedBoxes).map(cb => cb.value);
        
        if (ids.length === 0) {
            VulnScope.Notification.warning('请选择要删除的漏洞');
            return;
        }

        if (!confirm(`确定要删除选中的 ${ids.length} 个漏洞吗？此操作不可撤销。`)) {
            return;
        }

        try {
            for (const id of ids) {
                await VulnScope.API.vulnerabilities.delete(id);
            }
            
            VulnScope.Notification.success(`成功删除 ${ids.length} 个漏洞`);
            this.loadVulnerabilities();
        } catch (error) {
            console.error('删除失败:', error);
            VulnScope.Notification.error('删除失败，请稍后重试');
        }
    }

    async exportVulnerabilities() {
        try {
            const exportBtn = document.getElementById('export-vulnerabilities');
            if (exportBtn) {
                exportBtn.classList.add('loading');
                exportBtn.disabled = true;
            }

            const params = {
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
            const exportBtn = document.getElementById('export-vulnerabilities');
            if (exportBtn) {
                exportBtn.classList.remove('loading');
                exportBtn.disabled = false;
            }
        }
    }

    viewVulnerability(id) {
        window.location.href = `/vulnerabilities/${id}`;
    }

    editVulnerability(id) {
        window.location.href = `/vulnerabilities/${id}/edit`;
    }

    async deleteVulnerability(id) {
        if (!confirm('确定要删除这个漏洞吗？此操作不可撤销。')) {
            return;
        }

        try {
            await VulnScope.API.vulnerabilities.delete(id);
            VulnScope.Notification.success('漏洞删除成功');
            this.loadVulnerabilities();
        } catch (error) {
            console.error('删除失败:', error);
            VulnScope.Notification.error('删除失败，请稍后重试');
        }
    }

    initPagination() {
        const paginationContainer = document.getElementById('pagination-container');
        if (!paginationContainer) return;

        this.pagination = new VulnScope.Pagination(paginationContainer, {
            page: this.currentPage,
            limit: this.pageSize,
            total: this.totalCount,
            onChange: (page) => {
                this.currentPage = page;
                this.loadVulnerabilities();
                this.scrollToTop();
            }
        });
    }

    updatePagination() {
        if (this.pagination) {
            this.pagination.update({
                page: this.currentPage,
                total: this.totalCount
            });
        }
    }

    updateResultsInfo() {
        const resultsInfo = document.getElementById('results-info');
        if (!resultsInfo) return;

        const start = (this.currentPage - 1) * this.pageSize + 1;
        const end = Math.min(this.currentPage * this.pageSize, this.totalCount);

        resultsInfo.innerHTML = `
            显示第 <span class="font-semibold">${start}</span> - <span class="font-semibold">${end}</span> 条，
            共 <span class="font-semibold">${this.totalCount.toLocaleString()}</span> 条漏洞
        `;
    }

    renderError() {
        const tbody = document.getElementById('vulnerabilities-tbody');
        if (!tbody) return;

        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-red-500">
                    <i class="fas fa-exclamation-triangle text-3xl mb-3"></i>
                    <p>数据加载失败，请刷新重试</p>
                </td>
            </tr>
        `;
    }

    scrollToTop() {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showLoading() {
        VulnScope.Loading.show('#vulnerabilities-table', '加载中...');
    }

    hideLoading() {
        VulnScope.Loading.hide('#vulnerabilities-table');
    }
}

// 全局实例
let vulnerabilitiesPage;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('vulnerabilities-page')) {
        vulnerabilitiesPage = new VulnerabilitiesPage();
    }
}); 
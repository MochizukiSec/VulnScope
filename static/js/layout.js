/* VulnScope - 统一布局组件 */

class Layout {
    constructor() {
        this.currentPage = this.getCurrentPage();
        this.init();
    }

    getCurrentPage() {
        const path = window.location.pathname;
        if (path === '/' || path === '/dashboard') return 'dashboard';
        if (path.startsWith('/vulnerabilities')) return 'vulnerabilities';
        if (path.startsWith('/search')) return 'search';
        if (path.startsWith('/analytics')) return 'analytics';
        if (path.startsWith('/settings')) return 'settings';
        return 'unknown';
    }

    init() {
        this.addLayoutStyles();
        this.initializeUserInfo();
        this.bindNavigationEvents();
        this.updateActiveNavigation();
    }

    addLayoutStyles() {
        // 添加统一的样式类
        document.body.classList.add('vulnscope-layout');
        
        // 添加通用的CSS类
        const style = document.createElement('style');
        style.textContent = `
            .vulnscope-layout {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            /* 统一的渐变背景 */
            .navbar-gradient {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                position: relative;
            }
            
            .navbar-gradient::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(45deg, rgba(255,255,255,0.1) 0%, transparent 100%);
                pointer-events: none;
            }
            
            /* 统一的侧边栏样式 */
            .sidebar-nav-item {
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .sidebar-nav-item::before {
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                width: 0;
                background: linear-gradient(90deg, var(--primary-color), var(--primary-light));
                transition: width 0.3s ease;
            }
            
            .sidebar-nav-item.active::before {
                width: 4px;
            }
            
            .sidebar-nav-item:hover {
                background-color: rgba(59, 130, 246, 0.05);
                transform: translateX(4px);
            }
            
            .sidebar-nav-item.active {
                background-color: rgba(59, 130, 246, 0.1);
                color: var(--primary-color);
                font-weight: 600;
            }
            
            .sidebar-icon {
                transition: all 0.3s ease;
            }
            
            .sidebar-nav-item:hover .sidebar-icon {
                transform: scale(1.1);
                color: var(--primary-color);
            }
            
            /* 统一的收集状态指示器 */
            .status-indicator {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                margin-right: 0.5rem;
                animation: pulse 2s infinite;
            }
            
            .status-online { background-color: #10b981; }
            .status-warning { background-color: #f59e0b; }
            .status-offline { background-color: #ef4444; }
            
            /* 统一的页面标题样式 */
            .page-title {
                font-size: 2rem;
                font-weight: 700;
                color: var(--gray-900);
                margin-bottom: 1.5rem;
                background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            /* 统一的卡片动画 */
            .content-card {
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .content-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            }
        `;
        document.head.appendChild(style);
    }

    async initializeUserInfo() {
        try {
            // 获取用户信息
            const userInfo = await this.getUserInfo();
            if (userInfo) {
                this.updateUserDisplay(userInfo);
            }
        } catch (error) {
            console.error('获取用户信息失败:', error);
        }
    }

    async getUserInfo() {
        const token = VulnScope.Utils.getToken();
        if (!token) return null;
        
        try {
            const response = await VulnScope.API.user.profile();
            return response.success ? response.data : null;
        } catch (error) {
            return null;
        }
    }

    updateUserDisplay(userInfo) {
        // 更新导航栏中的用户信息
        const userDisplayElements = document.querySelectorAll('.user-display-name');
        userDisplayElements.forEach(element => {
            element.textContent = userInfo.username || '安全管理员';
        });

        // 更新用户头像
        const userAvatarElements = document.querySelectorAll('.user-avatar');
        userAvatarElements.forEach(element => {
            if (userInfo.avatar) {
                element.innerHTML = `<img src="${userInfo.avatar}" alt="用户头像" class="w-8 h-8 rounded-full">`;
            } else {
                element.innerHTML = `<div class="w-8 h-8 bg-white rounded-full flex items-center justify-center">
                    <i class="fas fa-user text-gray-600"></i>
                </div>`;
            }
        });
    }

    bindNavigationEvents() {
        // 绑定用户菜单事件
        document.addEventListener('click', (e) => {
            if (e.target.closest('.user-menu-trigger')) {
                this.toggleUserMenu();
            }
            
            if (e.target.closest('.logout-btn')) {
                this.logout();
            }
        });

        // 绑定移动端菜单事件
        const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
        if (mobileMenuBtn) {
            mobileMenuBtn.addEventListener('click', this.toggleMobileMenu);
        }
    }

    updateActiveNavigation() {
        // 移除所有活动状态
        document.querySelectorAll('.sidebar-nav-item').forEach(item => {
            item.classList.remove('active');
        });

        // 根据当前页面设置活动状态
        const currentNavItem = document.querySelector(`[data-page="${this.currentPage}"]`);
        if (currentNavItem) {
            currentNavItem.classList.add('active');
        }
    }

    toggleUserMenu() {
        const userMenu = document.querySelector('.user-dropdown-menu');
        if (userMenu) {
            userMenu.classList.toggle('hidden');
        }
    }

    toggleMobileMenu() {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.classList.toggle('mobile-open');
        }
    }

    async logout() {
        try {
            // 调用后端logout API
            try {
                await VulnScope.API.auth.logout();
            } catch (apiError) {
                // 即使API调用失败，我们仍然清除本地token
                console.warn('Logout API调用失败，但仍继续清除本地token:', apiError);
            }
            
            // 清除本地存储的认证信息
            VulnScope.Utils.clearToken();
            
            // 显示成功消息
            VulnScope.Notification.success('已成功退出登录');
            
            // 延迟重定向，让用户看到成功消息
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        } catch (error) {
            console.error('退出登录失败:', error);
            VulnScope.Notification.error('退出登录失败，请刷新页面重试');
            
            // 即使出错也尝试清除token并重定向
            VulnScope.Utils.clearToken();
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        }
    }

    // 静态方法：为页面添加统一的导航栏结构
    static createNavbar(title = 'VulnScope') {
        return `
            <nav class="navbar-gradient text-white shadow-lg">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div class="flex justify-between h-16">
                        <div class="flex items-center">
                            <button class="mobile-menu-btn md:hidden mr-3">
                                <i class="fas fa-bars text-xl"></i>
                            </button>
                            <i class="fas fa-shield-alt text-2xl mr-3"></i>
                            <span class="text-xl font-bold">${title}</span>
                            <span class="ml-2 text-sm opacity-75 hidden sm:inline">漏洞情报分析平台</span>
                        </div>
                        <div class="flex items-center space-x-4">
                            <div class="relative user-menu-trigger cursor-pointer">
                                <i class="fas fa-bell text-lg hover:text-yellow-300 transition-colors duration-200"></i>
                                <span class="absolute -top-2 -right-2 bg-red-500 text-xs rounded-full w-5 h-5 flex items-center justify-center animate-pulse">
                                    3
                                </span>
                            </div>
                            <div class="flex items-center space-x-2 user-menu-trigger cursor-pointer">
                                <div class="user-avatar">
                                    <div class="w-8 h-8 bg-white rounded-full flex items-center justify-center">
                                        <i class="fas fa-user text-gray-600"></i>
                                    </div>
                                </div>
                                <span class="text-sm user-display-name">安全管理员</span>
                                <i class="fas fa-chevron-down text-xs ml-1"></i>
                            </div>
                            <!-- 用户下拉菜单 -->
                            <div class="user-dropdown-menu absolute right-0 top-full mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50 hidden">
                                <a href="/profile" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                    <i class="fas fa-user mr-2"></i>个人资料
                                </a>
                                <a href="/settings" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                    <i class="fas fa-cog mr-2"></i>系统设置
                                </a>
                                <hr class="my-1">
                                <button class="logout-btn w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                    <i class="fas fa-sign-out-alt mr-2"></i>退出登录
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </nav>
        `;
    }

    // 静态方法：为页面添加统一的侧边栏结构
    static createSidebar() {
        return `
            <div class="w-64 bg-white shadow-lg min-h-screen sidebar">
                <div class="p-4">
                    <nav class="space-y-2">
                        <a href="/" class="sidebar-nav-item flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 rounded-lg" data-page="dashboard">
                            <i class="fas fa-tachometer-alt sidebar-icon mr-3"></i>
                            控制台
                        </a>
                        <a href="/vulnerabilities" class="sidebar-nav-item flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 rounded-lg" data-page="vulnerabilities">
                            <i class="fas fa-bug sidebar-icon mr-3"></i>
                            漏洞情报
                        </a>
                        <a href="/search" class="sidebar-nav-item flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 rounded-lg" data-page="search">
                            <i class="fas fa-search sidebar-icon mr-3"></i>
                            搜索分析
                        </a>
                        <a href="/analytics" class="sidebar-nav-item flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 rounded-lg" data-page="analytics">
                            <i class="fas fa-chart-line sidebar-icon mr-3"></i>
                            趋势分析
                        </a>
                        <a href="/settings" class="sidebar-nav-item flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 rounded-lg" data-page="settings">
                            <i class="fas fa-cogs sidebar-icon mr-3"></i>
                            系统设置
                        </a>
                    </nav>
                </div>
                
                <!-- 收集状态 -->
                <div class="p-4 border-t">
                    <h3 class="text-sm font-medium text-gray-500 mb-3">收集状态</h3>
                    <div class="space-y-2" id="collector-status">
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-600">NVD</span>
                            <span class="text-green-500">
                                <span class="status-indicator status-online"></span>活跃
                            </span>
                        </div>
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-600">Exploit-DB</span>
                            <span class="text-green-500">
                                <span class="status-indicator status-online"></span>活跃
                            </span>
                        </div>
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-600">CVE Details</span>
                            <span class="text-yellow-500">
                                <span class="status-indicator status-warning"></span>同步中
                            </span>
                        </div>
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-600">长亭漏洞库</span>
                            <span class="text-green-500">
                                <span class="status-indicator status-online"></span>活跃
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
}

// 导出到全局
window.VulnScope = window.VulnScope || {};
window.VulnScope.Layout = Layout;

// 页面加载时自动初始化
document.addEventListener('DOMContentLoaded', () => {
    // 只在非登录页面初始化布局
    if (!window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
        new Layout();
    }
}); 
-- 创建扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'security_engineer', 'security_analyst', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 创建漏洞表
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(50),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    cvss_score DECIMAL(3,1),
    cvss_vector TEXT,
    cwe_id VARCHAR(20),
    affected_products JSONB, -- JSON array
    reference_urls JSONB, -- JSON array
    exploits JSONB, -- JSON array
    patches JSONB, -- JSON array
    source VARCHAR(100) NOT NULL,
    source_url TEXT,
    published_date TIMESTAMPTZ NOT NULL,
    modified_date TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags JSONB, -- JSON array
    status VARCHAR(20) NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'analyzing', 'confirmed', 'patched', 'ignored'))
);

-- 创建系统设置表
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    nvd_api_key VARCHAR(255),
    github_token VARCHAR(255),
    collection_interval INTEGER NOT NULL DEFAULT 60,
    auto_update_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    notification_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    max_vulnerabilities_per_source INTEGER NOT NULL DEFAULT 1000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enable_aliyun_avd BOOLEAN DEFAULT TRUE,
    enable_chaitin_vuldb BOOLEAN DEFAULT TRUE,
    enable_qianxin_ti BOOLEAN DEFAULT TRUE,
    enable_threatbook_x BOOLEAN DEFAULT TRUE
);

-- 创建收集日志表
CREATE TABLE IF NOT EXISTS collection_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    vulnerabilities_collected INTEGER NOT NULL DEFAULT 0,
    errors TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

-- 创建索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities(source);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_collection_logs_source ON collection_logs(source);
CREATE INDEX IF NOT EXISTS idx_collection_logs_started_at ON collection_logs(started_at);

-- 插入默认系统设置
INSERT INTO system_settings (collection_interval, auto_update_enabled) 
VALUES (60, TRUE)
ON CONFLICT (id) DO NOTHING;

-- 创建默认管理员用户 (用户名: admin, 密码: admin123)
INSERT INTO users (id, username, email, password_hash, role) 
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@vulnscope.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewmVyPiWe5y1S/d6',
    'admin'
)
ON CONFLICT (username) DO NOTHING; 
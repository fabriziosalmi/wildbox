/**
 * Wildbox Security API - JavaScript utilities and interactions
 */

// Global configuration
const API_CONFIG = {
    baseUrl: '',
    timeout: 30000,
    getApiKey: function() {
        // Priority: session storage, then server-side rendered variable
        return sessionStorage.getItem('api_key') || window.API_KEY || '';
    },
    setApiKey: function(key) {
        if (key) {
            sessionStorage.setItem('api_key', key);
            window.API_KEY = key;
        } else {
            sessionStorage.removeItem('api_key');
            window.API_KEY = '';
        }
    },
    hasValidApiKey: function() {
        const key = this.getApiKey();
        return key && key.length > 0;
    }
};

// Utility functions
const Utils = {
    /**
     * Format timestamp to readable string
     */
    formatTimestamp: function(timestamp) {
        if (!timestamp) return 'N/A';
        return new Date(timestamp).toLocaleString();
    },

    /**
     * Format duration in seconds to readable string
     */
    formatDuration: function(seconds) {
        if (!seconds) return 'N/A';
        if (seconds < 60) return `${seconds.toFixed(2)}s`;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}m ${remainingSeconds.toFixed(0)}s`;
    },

    /**
     * Copy text to clipboard
     */
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Copied to clipboard', 'success');
        }).catch(() => {
            this.showToast('Failed to copy to clipboard', 'error');
        });
    },

    /**
     * Show toast notification
     */
    showToast: function(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer') || this.createToastContainer();
        
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Remove toast element after it's hidden
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    },

    /**
     * Create toast container if it doesn't exist
     */
    createToastContainer: function() {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
        return container;
    },

    /**
     * Validate form data against schema
     */
    validateFormData: function(data, schema) {
        const errors = [];
        
        if (!schema || !schema.properties) {
            return errors;
        }

        // Check required fields
        if (schema.required) {
            for (const field of schema.required) {
                if (!data[field] || data[field] === '') {
                    errors.push(`${field} is required`);
                }
            }
        }

        // Validate field types and constraints
        for (const [fieldName, fieldSchema] of Object.entries(schema.properties)) {
            const value = data[fieldName];
            
            if (value !== undefined && value !== '') {
                // Type validation
                if (fieldSchema.type === 'integer' && !Number.isInteger(Number(value))) {
                    errors.push(`${fieldName} must be an integer`);
                } else if (fieldSchema.type === 'number' && isNaN(Number(value))) {
                    errors.push(`${fieldName} must be a number`);
                }

                // Range validation
                if (fieldSchema.minimum !== undefined && Number(value) < fieldSchema.minimum) {
                    errors.push(`${fieldName} must be at least ${fieldSchema.minimum}`);
                }
                if (fieldSchema.maximum !== undefined && Number(value) > fieldSchema.maximum) {
                    errors.push(`${fieldName} must be at most ${fieldSchema.maximum}`);
                }

                // Enum validation
                if (fieldSchema.enum && !fieldSchema.enum.includes(value)) {
                    errors.push(`${fieldName} must be one of: ${fieldSchema.enum.join(', ')}`);
                }
            }
        }

        return errors;
    }
};

// API interaction functions
const API = {
    /**
     * Make authenticated API request
     */
    request: async function(endpoint, options = {}) {
        const url = `${API_CONFIG.baseUrl}${endpoint}`;
        const apiKey = API_CONFIG.getApiKey();
        
        if (!apiKey) {
            const error = new Error('API key not configured. Please go to Settings to configure your API key.');
            error.isAuthError = true;
            throw error;
        }
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            }
        };

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    const error = new Error('Invalid API key. Please check your API key in Settings.');
                    error.isAuthError = true;
                    throw error;
                }
                
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            
            // Show user-friendly message for auth errors
            if (error.isAuthError) {
                Utils.showToast(error.message, 'error');
                // Optionally redirect to settings
                if (confirm(error.message + '\n\nWould you like to go to Settings now?')) {
                    window.location.href = '/settings';
                }
            }
            
            throw error;
        }
    },

    /**
     * Get list of available tools
     */
    getTools: async function() {
        return await this.request('/api/tools');
    },

    /**
     * Get tool information
     */
    getToolInfo: async function(toolName) {
        return await this.request(`/api/tools/${toolName}/info`);
    },

    /**
     * Execute a security tool
     */
    executeTool: async function(toolName, inputData) {
        return await this.request(`/api/tools/${toolName}`, {
            method: 'POST',
            body: JSON.stringify(inputData)
        });
    }
};

// Form generation and handling
const FormHandler = {
    /**
     * Generate HTML form fields from JSON schema
     */
    generateFormFields: function(schema, containerId) {
        const container = document.getElementById(containerId);
        
        if (!schema || !schema.properties) {
            container.innerHTML = '<div class="alert alert-warning">No input schema available.</div>';
            return;
        }

        let html = '';
        for (const [fieldName, fieldSchema] of Object.entries(schema.properties)) {
            html += this.generateFieldHTML(fieldName, fieldSchema, schema.required || []);
        }

        container.innerHTML = html;
    },

    /**
     * Generate HTML for a single form field
     */
    generateFieldHTML: function(fieldName, fieldSchema, requiredFields) {
        const isRequired = requiredFields.includes(fieldName);
        const fieldType = fieldSchema.type || 'string';
        const fieldDescription = fieldSchema.description || '';
        const fieldExample = fieldSchema.example || '';
        const defaultValue = fieldSchema.default || '';
        const label = fieldName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

        let inputHTML = '';
        
        if (fieldType === 'integer' || fieldType === 'number') {
            const min = fieldSchema.minimum !== undefined ? `min="${fieldSchema.minimum}"` : '';
            const max = fieldSchema.maximum !== undefined ? `max="${fieldSchema.maximum}"` : '';
            inputHTML = `
                <input type="number" 
                       class="form-control" 
                       id="${fieldName}" 
                       name="${fieldName}"
                       placeholder="${fieldExample}"
                       value="${defaultValue}"
                       ${min} ${max}
                       ${isRequired ? 'required' : ''}/>
            `;
        } else if (fieldSchema.enum) {
            inputHTML = `<select class="form-select" id="${fieldName}" name="${fieldName}" ${isRequired ? 'required' : ''}>`;
            if (!isRequired) {
                inputHTML += '<option value="">-- Select an option --</option>';
            }
            for (const option of fieldSchema.enum) {
                const selected = option === defaultValue ? 'selected' : '';
                inputHTML += `<option value="${option}" ${selected}>${option}</option>`;
            }
            inputHTML += '</select>';
        } else if (fieldType === 'boolean') {
            inputHTML = `
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="${fieldName}" name="${fieldName}" ${defaultValue ? 'checked' : ''}>
                    <label class="form-check-label" for="${fieldName}">
                        Enable ${label}
                    </label>
                </div>
            `;
        } else {
            inputHTML = `
                <input type="text" 
                       class="form-control" 
                       id="${fieldName}" 
                       name="${fieldName}"
                       placeholder="${fieldExample}"
                       value="${defaultValue}"
                       ${isRequired ? 'required' : ''}/>
            `;
        }

        return `
            <div class="mb-3">
                <label for="${fieldName}" class="form-label">
                    ${label}
                    ${isRequired ? '<span class="text-danger">*</span>' : ''}
                </label>
                ${inputHTML}
                ${fieldDescription ? `<div class="form-text">${fieldDescription}</div>` : ''}
            </div>
        `;
    },

    /**
     * Extract form data and convert to appropriate types
     */
    extractFormData: function(formElement, schema) {
        const formData = new FormData(formElement);
        const data = {};

        for (const [key, value] of formData.entries()) {
            const fieldSchema = schema.properties[key];
            
            if (fieldSchema) {
                if (fieldSchema.type === 'integer') {
                    data[key] = parseInt(value, 10);
                } else if (fieldSchema.type === 'number') {
                    data[key] = parseFloat(value);
                } else if (fieldSchema.type === 'boolean') {
                    data[key] = formData.has(key);
                } else {
                    data[key] = value;
                }
            }
        }

        return data;
    }
};

// Results display functions
const ResultsRenderer = {
    /**
     * Render tool execution results
     */
    renderResults: function(results, containerId) {
        const container = document.getElementById(containerId);
        
        let html = this.renderSummary(results);
        
        if (results.open_ports && results.open_ports.length > 0) {
            html += this.renderOpenPorts(results.open_ports);
        }
        
        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            html += this.renderVulnerabilities(results.vulnerabilities);
        }
        
        if (results.recommendations && results.recommendations.length > 0) {
            html += this.renderRecommendations(results.recommendations);
        }

        container.innerHTML = html;
    },

    /**
     * Render execution summary
     */
    renderSummary: function(results) {
        const statusBadge = results.status === 'success' ? 'success' : 'danger';
        
        return `
            <div class="row mb-4">
                <div class="col-md-6">
                    <h6><i class="fas fa-info-circle me-1"></i>Execution Summary</h6>
                    <ul class="list-unstyled">
                        <li><strong>Target:</strong> ${results.target || 'N/A'}</li>
                        <li><strong>Status:</strong> <span class="badge bg-${statusBadge}">${results.status || 'unknown'}</span></li>
                        <li><strong>Duration:</strong> ${Utils.formatDuration(results.duration)}</li>
                        <li><strong>Timestamp:</strong> ${Utils.formatTimestamp(results.timestamp)}</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6><i class="fas fa-chart-bar me-1"></i>Key Metrics</h6>
                    ${this.renderFindings(results.findings)}
                </div>
            </div>
        `;
    },

    /**
     * Render findings section
     */
    renderFindings: function(findings) {
        if (!findings) return '<p class="text-muted">No findings available</p>';
        
        let html = '<ul class="list-unstyled">';
        for (const [key, value] of Object.entries(findings)) {
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            html += `<li><strong>${displayKey}:</strong> ${value}</li>`;
        }
        html += '</ul>';
        
        return html;
    },

    /**
     * Render open ports table
     */
    renderOpenPorts: function(openPorts) {
        let html = `
            <div class="mt-4">
                <h6><i class="fas fa-network-wired me-1"></i>Open Ports (${openPorts.length})</h6>
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
        `;
        
        for (const port of openPorts) {
            html += `
                <tr>
                    <td><strong>${port.port}</strong></td>
                    <td><span class="badge bg-success">${port.state}</span></td>
                    <td>${port.service || '<em>unknown</em>'}</td>
                    <td>${port.version || '<em>N/A</em>'}</td>
                </tr>
            `;
        }
        
        html += '</tbody></table></div></div>';
        return html;
    },

    /**
     * Render vulnerabilities list
     */
    renderVulnerabilities: function(vulnerabilities) {
        let html = `
            <div class="mt-4">
                <h6><i class="fas fa-exclamation-triangle me-1 text-warning"></i>Vulnerabilities (${vulnerabilities.length})</h6>
                <div class="list-group">
        `;
        
        for (const vuln of vulnerabilities) {
            html += `
                <div class="list-group-item list-group-item-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>${vuln}
                </div>
            `;
        }
        
        html += '</div></div>';
        return html;
    },

    /**
     * Render recommendations list
     */
    renderRecommendations: function(recommendations) {
        let html = `
            <div class="mt-4">
                <h6><i class="fas fa-lightbulb me-1 text-info"></i>Recommendations (${recommendations.length})</h6>
                <div class="list-group">
        `;
        
        for (const rec of recommendations) {
            html += `
                <div class="list-group-item list-group-item-info">
                    <i class="fas fa-lightbulb me-2"></i>${rec}
                </div>
            `;
        }
        
        html += '</div></div>';
        return html;
    }
};

// API Key Management utilities
const ApiKeyManager = {
    /**
     * Check if API key is configured and valid
     */
    isConfigured: function() {
        return API_CONFIG.hasValidApiKey();
    },

    /**
     * Validate API key by making a test request
     */
    validate: async function(apiKey = null) {
        const keyToTest = apiKey || API_CONFIG.getApiKey();
        
        if (!keyToTest) {
            return { valid: false, error: 'No API key provided' };
        }

        try {
            const response = await fetch('/api/tools', {
                headers: {
                    'Authorization': `Bearer ${keyToTest}`
                }
            });

            if (response.ok) {
                return { valid: true };
            } else {
                return { valid: false, error: 'Invalid API key' };
            }
        } catch (error) {
            return { valid: false, error: 'Connection failed: ' + error.message };
        }
    },

    /**
     * Show API key warning if not configured
     */
    showWarningIfNeeded: function() {
        if (!this.isConfigured()) {
            Utils.showToast(
                'API key not configured. Go to Settings to configure your API key.',
                'warning'
            );
            return true;
        }
        return false;
    },

    /**
     * Prompt user to configure API key
     */
    promptConfiguration: function() {
        if (confirm('API key is required to use this feature.\n\nWould you like to configure it now?')) {
            window.location.href = '/settings';
        }
    }
};

// Page-specific initialization
const PageInit = {
    /**
     * Initialize the dashboard page
     */
    dashboard: function() {
        // Check API key status on dashboard
        ApiKeyManager.showWarningIfNeeded();
    },

    /**
     * Initialize tool pages
     */
    tool: function() {
        // Ensure API key is configured before allowing tool execution
        if (!ApiKeyManager.isConfigured()) {
            const executeBtn = document.getElementById('executeBtn');
            if (executeBtn) {
                executeBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    ApiKeyManager.promptConfiguration();
                });
            }
        }
    }
};

// Initialize tooltips and other Bootstrap components
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});

// Export to global scope for use in templates
window.Utils = Utils;
window.API = API;
window.FormHandler = FormHandler;
window.ResultsRenderer = ResultsRenderer;
window.ApiKeyManager = ApiKeyManager;
window.PageInit = PageInit;
window.ToolSearch = ToolSearch;
window.quickSearch = quickSearch;
window.getCategoryLabel = getCategoryLabel;

// Initialize page-specific features
document.addEventListener('DOMContentLoaded', function() {
    const bodyId = document.body.id;
    
    if (bodyId) {
        const initFunction = PageInit[bodyId];
        if (typeof initFunction === 'function') {
            initFunction();
        }
    }
});

// Tool information modal functionality
function showToolInfo(toolName) {
    API.getToolInfo(toolName)
        .then(toolInfo => {
            const modalHtml = `
                <div class="modal fade" id="toolInfoModal" tabindex="-1" aria-labelledby="toolInfoModalLabel" aria-hidden="true">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="toolInfoModalLabel">
                                    <i class="fas fa-info-circle me-2"></i>${toolInfo.display_name || toolInfo.name}
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6><i class="fas fa-tag me-2"></i>Basic Information</h6>
                                        <ul class="list-unstyled">
                                            <li><strong>Name:</strong> ${toolInfo.name}</li>
                                            <li><strong>Version:</strong> ${toolInfo.version}</li>
                                            <li><strong>Author:</strong> ${toolInfo.author}</li>
                                            <li><strong>Category:</strong> ${toolInfo.category}</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-6">
                                        <h6><i class="fas fa-cog me-2"></i>Technical Details</h6>
                                        <ul class="list-unstyled">
                                            <li><strong>Endpoint:</strong> <code>${toolInfo.endpoint}</code></li>
                                            <li><strong>Status:</strong> <span class="badge bg-success">Active</span></li>
                                        </ul>
                                    </div>
                                </div>
                                <hr>
                                <h6><i class="fas fa-file-alt me-2"></i>Description</h6>
                                <p>${toolInfo.description}</p>
                                ${toolInfo.tags && toolInfo.tags.length > 0 ? `
                                <h6><i class="fas fa-tags me-2"></i>Tags</h6>
                                <div class="mb-3">
                                    ${toolInfo.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('')}
                                </div>
                                ` : ''}
                            </div>
                            <div class="modal-footer">
                                <a href="${toolInfo.endpoint.replace('/api', '')}" class="btn btn-primary">
                                    <i class="fas fa-rocket me-2"></i>Launch Tool
                                </a>
                                <a href="/docs#/${toolInfo.name}" class="btn btn-outline-primary" target="_blank">
                                    <i class="fas fa-code me-2"></i>View API Docs
                                </a>
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal if any
            const existingModal = document.getElementById('toolInfoModal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Add modal to body
            document.body.insertAdjacentHTML('beforeend', modalHtml);
            
            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('toolInfoModal'));
            modal.show();
            
            // Clean up modal after hiding
            document.getElementById('toolInfoModal').addEventListener('hidden.bs.modal', function() {
                this.remove();
            });
        })
        .catch(error => {
            Utils.showToast(`Failed to load tool information: ${error.message}`, 'error');
        });
}

// Filter tools functionality
function filterTools(category) {
    const toolCards = document.querySelectorAll('.tool-card');
    
    toolCards.forEach(card => {
        if (category === 'all' || card.dataset.category.includes(category.toLowerCase())) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
    
    Utils.showToast(
        category === 'all' ? 'Showing all tools' : `Filtered by: ${category}`,
        'info'
    );
}

// Refresh tools functionality
function refreshTools() {
    Utils.showToast('Refreshing tools...', 'info');
    setTimeout(() => {
        window.location.reload();
    }, 1000);
}

// Category mapping function for proper display labels
function getCategoryLabel(category) {
        const categoryMap = {
        'api_security': 'API Security',
        'api security': 'API Security',
        'authentication': 'Authentication',
        'automation': 'Automation',
        'cloud_security': 'Cloud Security',
        'cloud security': 'Cloud Security',
        'compliance': 'Compliance',
        'container_security': 'Container Security',
        'container security': 'Container Security',
        'crypto_analysis': 'Cryptography',
        'crypto analysis': 'Cryptography',
        'cryptography': 'Cryptography',
        'data_analysis': 'Data Analysis',
        'data analysis': 'Data Analysis',
        'database_security': 'Database Security',
        'database security': 'Database Security',
        'email_security': 'Email Security',
        'email security': 'Email Security',
        'general': 'General',
        'incident_response': 'Incident Response',
        'incident response': 'Incident Response',
        'iot_security': 'IoT Security',
        'iot security': 'IoT Security',
        'malware_analysis': 'Malware Analysis',
        'malware analysis': 'Malware Analysis',
        'mobile_security': 'Mobile Security',
        'mobile security': 'Mobile Security',
        'network_reconnaissance': 'Network Reconnaissance',
        'network reconnaissance': 'Network Reconnaissance',
        'network_scanning': 'Network Scanning',
        'network scanning': 'Network Scanning',
        'network_security': 'Network Security',
        'network security': 'Network Security',
        'network_vulnerability': 'Network Vulnerability',
        'network vulnerability': 'Network Vulnerability',
        'osint': 'OSINT',
        'reconnaissance': 'Reconnaissance',
        'security_analysis': 'Security Analysis',
        'security analysis': 'Security Analysis',
        'threat_intelligence': 'Threat Intelligence',
        'threat intelligence': 'Threat Intelligence',
        'vulnerability_assessment': 'Vulnerability Assessment',
        'vulnerability assessment': 'Vulnerability Assessment',
        'web_reconnaissance': 'Web Reconnaissance',
        'web reconnaissance': 'Web Reconnaissance',
        'web_security': 'Web Security',
        'web security': 'Web Security',
    };
    
    // Return mapped label or format the category nicely if not found
    return categoryMap[category.toLowerCase()] || 
           category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Make it available globally
window.getCategoryLabel = getCategoryLabel;

// Tool Search and Autocomplete functionality
const ToolSearch = {
    // Cache for tools data
    toolsData: [],
    searchInput: null,
    searchResults: null,
    clearBtn: null,
    currentFocus: -1,
    
    /**
     * Initialize search functionality
     */
    init: function() {
        this.searchInput = document.getElementById('toolSearchInput');
        this.searchResults = document.getElementById('searchResults');
        this.clearBtn = document.getElementById('clearSearchBtn');
        
        if (!this.searchInput || !this.searchResults) return;
        
        this.loadToolsData();
        this.bindEvents();
    },
    
    /**
     * Load tools data from the DOM
     */
    loadToolsData: function() {
        const toolCards = document.querySelectorAll('.tool-card');
        this.toolsData = [];
        
        toolCards.forEach(card => {
            const nameElement = card.querySelector('h5');
            const descElement = card.querySelector('.card-text');
            const categoryElement = card.querySelector('.category-badge');
            const linkElement = card.querySelector('.btn-primary[href]');
            
            if (nameElement && descElement && linkElement) {
                const toolData = {
                    name: nameElement.textContent.trim(),
                    description: descElement.textContent.trim(),
                    category: categoryElement ? categoryElement.textContent.trim() : 'General',
                    url: linkElement.getAttribute('href'),
                    element: card,
                    keywords: this.generateKeywords(nameElement.textContent, descElement.textContent, categoryElement?.textContent)
                };
                this.toolsData.push(toolData);
            }
        });
    },
    
    /**
     * Generate searchable keywords from tool data
     */
    generateKeywords: function(name, description, category) {
        const keywords = [];
        
        // Add name variations
        keywords.push(name.toLowerCase());
        keywords.push(...name.toLowerCase().split(/[\s_-]+/));
        
        // Add description words
        keywords.push(...description.toLowerCase().split(/\s+/).filter(word => word.length > 2));
        
        // Add category
        if (category) {
            keywords.push(category.toLowerCase());
            keywords.push(...category.toLowerCase().split(/[\s_-]+/));
        }
        
        // Add common synonyms
        const synonyms = this.getSynonyms(name.toLowerCase());
        keywords.push(...synonyms);
        
        return [...new Set(keywords)]; // Remove duplicates
    },
    
    /**
     * Get synonyms for common security terms
     */
    getSynonyms: function(name) {
        const synonymMap = {
            'scanner': ['scan', 'scanning', 'check', 'analyze'],
            'analyzer': ['analysis', 'analyze', 'examination', 'inspect'],
            'network': ['net', 'networking', 'connection'],
            'vulnerability': ['vuln', 'bug', 'weakness', 'flaw'],
            'security': ['sec', 'protection', 'defense'],
            'osint': ['intelligence', 'recon', 'reconnaissance'],
            'web': ['website', 'http', 'https', 'www'],
            'ssl': ['tls', 'certificate', 'cert'],
            'dns': ['domain', 'nameserver'],
            'port': ['service', 'socket'],
            'sql': ['database', 'db', 'injection'],
            'xss': ['cross-site', 'scripting'],
            'jwt': ['token', 'json'],
            'hash': ['hashing', 'crypto', 'checksum'],
            'password': ['pass', 'credential', 'auth'],
            'email': ['mail', 'smtp', 'message'],
            'mobile': ['android', 'ios', 'app'],
            'api': ['endpoint', 'rest', 'service'],
            'cloud': ['aws', 'azure', 'gcp'],
            'container': ['docker', 'kubernetes'],
            'malware': ['virus', 'trojan', 'threat']
        };
        
        const synonyms = [];
        for (const [key, values] of Object.entries(synonymMap)) {
            if (name.includes(key)) {
                synonyms.push(...values);
            }
        }
        return synonyms;
    },
    
    /**
     * Bind search events
     */
    bindEvents: function() {
        // Input event for real-time search
        this.searchInput.addEventListener('input', (e) => {
            const query = e.target.value.trim();
            if (query.length > 0) {
                this.performSearch(query);
                this.showClearButton();
            } else {
                this.hideResults();
                this.hideClearButton();
                this.showAllTools();
            }
        });
        
        // Keyboard navigation
        this.searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateResults(1);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateResults(-1);
            } else if (e.key === 'Enter') {
                e.preventDefault();
                this.selectCurrentResult();
            } else if (e.key === 'Escape') {
                this.hideResults();
                this.searchInput.blur();
            }
        });
        
        // Clear button
        if (this.clearBtn) {
            this.clearBtn.addEventListener('click', () => {
                this.clearSearch();
            });
        }
        
        // Hide results when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.searchInput.contains(e.target) && !this.searchResults.contains(e.target)) {
                this.hideResults();
            }
        });
        
        // Show results when focusing input if there's a query
        this.searchInput.addEventListener('focus', () => {
            if (this.searchInput.value.trim().length > 0) {
                this.performSearch(this.searchInput.value.trim());
            }
        });
    },
    
    /**
     * Perform search and show results
     */
    performSearch: function(query) {
        const results = this.searchTools(query);
        this.displayResults(results, query);
        this.filterToolsOnPage(results);
    },
    
    /**
     * Search tools by query
     */
    searchTools: function(query) {
        const searchTerms = query.toLowerCase().split(/\s+/);
        const results = [];
        
        this.toolsData.forEach(tool => {
            let score = 0;
            let matchedTerms = 0;
            
            searchTerms.forEach(term => {
                // Exact name match (highest score)
                if (tool.name.toLowerCase().includes(term)) {
                    score += 10;
                    matchedTerms++;
                }
                
                // Category match
                if (tool.category.toLowerCase().includes(term)) {
                    score += 8;
                    matchedTerms++;
                }
                
                // Description match
                if (tool.description.toLowerCase().includes(term)) {
                    score += 5;
                    matchedTerms++;
                }
                
                // Keyword match
                if (tool.keywords.some(keyword => keyword.includes(term))) {
                    score += 3;
                    matchedTerms++;
                }
                
                // Partial name match
                if (tool.name.toLowerCase().startsWith(term)) {
                    score += 7;
                }
            });
            
            // Only include if all search terms matched something
            if (matchedTerms >= searchTerms.length) {
                results.push({ ...tool, score });
            }
        });
        
        // Sort by score (descending)
        return results.sort((a, b) => b.score - a.score);
    },
    
    /**
     * Display search results
     */
    displayResults: function(results, query) {
        if (results.length === 0) {
            this.searchResults.innerHTML = `
                <div class="p-3 text-center text-muted">
                    <i class="fas fa-search me-2"></i>
                    No tools found for "${query}"
                    <div class="mt-2 small">
                        Try searching for categories like "scanner", "analyzer", or "network"
                    </div>
                </div>
            `;
        } else {
            const maxResults = Math.min(results.length, 8);
            let html = '';
            
            for (let i = 0; i < maxResults; i++) {
                const tool = results[i];
                const highlightedName = this.highlightMatches(tool.name, query);
                const highlightedDesc = this.truncateAndHighlight(tool.description, query, 80);
                
                html += `
                    <div class="search-result-item p-3 border-bottom hover-bg" data-url="${tool.url}" data-index="${i}">
                        <div class="d-flex align-items-start justify-content-between">
                            <div class="flex-grow-1">
                                <div class="fw-bold text-primary mb-1">${highlightedName}</div>
                                <div class="text-muted small mb-2">${highlightedDesc}</div>
                                <div class="d-flex align-items-center gap-2">
                                    <span class="badge bg-light text-dark">${tool.category}</span>
                                    <span class="text-muted small">
                                        <i class="fas fa-rocket me-1"></i>Launch
                                    </span>
                                </div>
                            </div>
                            <div class="text-muted">
                                <i class="fas fa-arrow-right"></i>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            if (results.length > maxResults) {
                html += `
                    <div class="p-3 text-center text-muted border-top bg-light">
                        <small>Showing ${maxResults} of ${results.length} results</small>
                    </div>
                `;
            }
            
            this.searchResults.innerHTML = html;
            
            // Add click handlers
            this.searchResults.querySelectorAll('.search-result-item').forEach(item => {
                item.addEventListener('click', () => {
                    window.location.href = item.dataset.url;
                });
            });
        }
        
        this.showResults();
        this.currentFocus = -1;
    },
    
    /**
     * Highlight matching text
     */
    highlightMatches: function(text, query) {
        const terms = query.toLowerCase().split(/\s+/);
        let highlightedText = text;
        
        terms.forEach(term => {
            const regex = new RegExp(`(${this.escapeRegex(term)})`, 'gi');
            highlightedText = highlightedText.replace(regex, '<mark>$1</mark>');
        });
        
        return highlightedText;
    },
    
    /**
     * Truncate and highlight description
     */
    truncateAndHighlight: function(text, query, maxLength) {
        let truncated = text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
        return this.highlightMatches(truncated, query);
    },
    
    /**
     * Escape regex special characters
     */
    escapeRegex: function(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    },
    
    /**
     * Filter tools on the page
     */
    filterToolsOnPage: function(results) {
        const toolCards = document.querySelectorAll('.tool-card');
        const resultUrls = new Set(results.map(r => r.url));
        
        toolCards.forEach(card => {
            const toolLink = card.querySelector('.btn-primary[href]');
            if (toolLink && resultUrls.has(toolLink.getAttribute('href'))) {
                card.style.display = 'block';
                card.classList.add('search-match');
            } else {
                card.style.display = 'none';
                card.classList.remove('search-match');
            }
        });
    },
    
    /**
     * Show all tools (reset filter)
     */
    showAllTools: function() {
        const toolCards = document.querySelectorAll('.tool-card');
        toolCards.forEach(card => {
            card.style.display = 'block';
            card.classList.remove('search-match');
        });
    },
    
    /**
     * Navigate search results with keyboard
     */
    navigateResults: function(direction) {
        const items = this.searchResults.querySelectorAll('.search-result-item');
        if (items.length === 0) return;
        
        // Remove current focus
        if (this.currentFocus >= 0 && items[this.currentFocus]) {
            items[this.currentFocus].classList.remove('search-result-active');
        }
        
        // Update focus
        this.currentFocus += direction;
        if (this.currentFocus >= items.length) this.currentFocus = 0;
        if (this.currentFocus < 0) this.currentFocus = items.length - 1;
        
        // Add new focus
        items[this.currentFocus].classList.add('search-result-active');
        items[this.currentFocus].scrollIntoView({ block: 'nearest' });
    },
    
    /**
     * Select current focused result
     */
    selectCurrentResult: function() {
        const items = this.searchResults.querySelectorAll('.search-result-item');
        if (this.currentFocus >= 0 && items[this.currentFocus]) {
            window.location.href = items[this.currentFocus].dataset.url;
        }
    },
    
    /**
     * Show search results dropdown
     */
    showResults: function() {
        this.searchResults.style.display = 'block';
    },
    
    /**
     * Hide search results dropdown
     */
    hideResults: function() {
        this.searchResults.style.display = 'none';
        this.currentFocus = -1;
    },
    
    /**
     * Show clear button
     */
    showClearButton: function() {
        if (this.clearBtn) {
            this.clearBtn.style.display = 'block';
        }
    },
    
    /**
     * Hide clear button
     */
    hideClearButton: function() {
        if (this.clearBtn) {
            this.clearBtn.style.display = 'none';
        }
    },
    
    /**
     * Clear search
     */
    clearSearch: function() {
        this.searchInput.value = '';
        this.hideResults();
        this.hideClearButton();
        this.showAllTools();
        this.searchInput.focus();
    }
};

/**
 * Quick search function for category buttons
 */
function quickSearch(category) {
    const searchInput = document.getElementById('toolSearchInput');
    if (searchInput) {
        searchInput.value = category;
        searchInput.focus();
        ToolSearch.performSearch(category);
        ToolSearch.showClearButton();
    }
}

// ...existing code...

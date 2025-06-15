/**
 * Wildbox Security API - JavaScript utilities and interactions
 */

// Global configuration
const API_CONFIG = {
    baseUrl: '',
    timeout: 30000,
    getApiKey: function() {
        // Get API key from a secure source (e.g., server-side rendered variable)
        return window.API_KEY || sessionStorage.getItem('api_key') || '';
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
            throw new Error('API key not available. Please contact administrator.');
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
                const error = await response.json();
                throw new Error(error.detail || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
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

/**
 * Scam Detection System - Frontend Application
 */

// API helper
const api = {
    async request(url, options = {}) {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
            ...options,
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Request failed' }));
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        return response.json();
    },

    async get(url) {
        return this.request(url);
    },

    async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },

    async delete(url) {
        return this.request(url, { method: 'DELETE' });
    },
};

// Toast notifications
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Tab navigation
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;

            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');

            // Load data when switching tabs
            if (tabId === 'patterns') {
                loadPatterns();
            } else if (tabId === 'config') {
                loadConfig();
            }
        });
    });
}

// Analyze functionality
function initAnalyze() {
    const form = document.getElementById('analyze-form');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultsContainer = document.getElementById('results-container');
    const resultsContent = document.getElementById('results-content');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const content = document.getElementById('message-content').value.trim();
        if (!content) {
            showToast('Please enter a message to analyze', 'warning');
            return;
        }

        const title = document.getElementById('message-title').value.trim() || null;
        const author = document.getElementById('message-author').value.trim() || null;

        // Show loading state
        analyzeBtn.disabled = true;
        analyzeBtn.querySelector('.btn-text').style.display = 'none';
        analyzeBtn.querySelector('.btn-loading').style.display = 'inline';

        try {
            const result = await api.post('/api/analyze', { content, title, author });
            displayResults(result);
            resultsContainer.style.display = 'block';
            resultsContainer.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            showToast(`Analysis failed: ${error.message}`, 'error');
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.querySelector('.btn-text').style.display = 'inline';
            analyzeBtn.querySelector('.btn-loading').style.display = 'none';
        }
    });
}

function displayResults(result) {
    const resultsContent = document.getElementById('results-content');
    const riskLevel = result.risk_level;

    let html = `
        <div class="result-summary risk-${riskLevel}">
            <div class="result-title">
                <span class="risk-badge risk-${riskLevel}">${riskLevel}</span>
                ${result.is_scam ? 'Potential Scam Detected' : 'No Scam Detected'}
            </div>
            <p class="result-text">${result.summary || 'Analysis complete.'}</p>
        </div>
    `;

    if (result.matched_patterns && result.matched_patterns.length > 0) {
        html += '<h3 style="margin-bottom: 12px;">Matched Patterns</h3>';

        result.matched_patterns.forEach(match => {
            const confidencePercent = Math.round(match.confidence * 100);
            const confidenceClass = match.confidence < 0.4 ? 'low' :
                                   match.confidence < 0.7 ? 'medium' : 'high';

            html += `
                <div class="pattern-match">
                    <div class="pattern-match-header">
                        <span class="pattern-match-name">${match.pattern_name}</span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="font-size: 0.875rem; color: var(--text-muted);">${confidencePercent}%</span>
                            <div class="confidence-bar">
                                <div class="confidence-fill confidence-${confidenceClass}"
                                     style="width: ${confidencePercent}%"></div>
                            </div>
                        </div>
                    </div>
                    ${match.explanation ? `<div class="explanation">${match.explanation}</div>` : ''}
                    ${match.evidence && match.evidence.length > 0 ? `
                        <ul class="evidence-list">
                            ${match.evidence.map(e => `<li>"${e}"</li>`).join('')}
                        </ul>
                    ` : ''}
                </div>
            `;
        });
    }

    resultsContent.innerHTML = html;
}

// Patterns management
async function loadPatterns() {
    const patternsList = document.getElementById('patterns-list');
    patternsList.innerHTML = '<div class="empty-state">Loading patterns...</div>';

    try {
        const patterns = await api.get('/api/patterns');

        if (patterns.length === 0) {
            patternsList.innerHTML = `
                <div class="empty-state">
                    <h3>No patterns configured</h3>
                    <p>Add a pattern or reset to defaults to get started.</p>
                </div>
            `;
            return;
        }

        patternsList.innerHTML = patterns.map(p => createPatternItem(p)).join('');

        // Add event listeners
        patternsList.querySelectorAll('.toggle-details').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const item = e.target.closest('.pattern-item');
                item.classList.toggle('expanded');
                e.target.textContent = item.classList.contains('expanded') ? 'Hide details' : 'Show details';
            });
        });

        patternsList.querySelectorAll('.edit-pattern').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const name = e.target.dataset.name;
                const pattern = patterns.find(p => p.name === name);
                if (pattern) openPatternModal(pattern);
            });
        });

        patternsList.querySelectorAll('.delete-pattern').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const name = e.target.dataset.name;
                if (confirm(`Delete pattern "${name}"?`)) {
                    try {
                        await api.delete(`/api/patterns/${encodeURIComponent(name)}`);
                        showToast(`Pattern "${name}" deleted`, 'success');
                        loadPatterns();
                    } catch (error) {
                        showToast(`Failed to delete: ${error.message}`, 'error');
                    }
                }
            });
        });
    } catch (error) {
        patternsList.innerHTML = `
            <div class="empty-state">
                <h3>Failed to load patterns</h3>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function createPatternItem(pattern) {
    return `
        <div class="pattern-item">
            <div class="pattern-item-header">
                <span class="pattern-item-title">${pattern.name}</span>
                <span class="pattern-item-severity severity-${pattern.severity}">${pattern.severity}</span>
            </div>
            <p class="pattern-item-description">${pattern.description}</p>
            <button class="toggle-details">Show details</button>
            <div class="pattern-item-details">
                ${pattern.indicators && pattern.indicators.length > 0 ? `
                    <div class="pattern-item-section">
                        <h4>Indicators</h4>
                        <ul>
                            ${pattern.indicators.map(i => `<li>${i}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${pattern.examples && pattern.examples.length > 0 ? `
                    <div class="pattern-item-section">
                        <h4>Examples</h4>
                        <ul>
                            ${pattern.examples.map(e => `<li>${e}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                <div class="pattern-item-actions">
                    <button class="btn btn-sm btn-secondary edit-pattern" data-name="${pattern.name}">Edit</button>
                    <button class="btn btn-sm btn-danger delete-pattern" data-name="${pattern.name}">Delete</button>
                </div>
            </div>
        </div>
    `;
}

function initPatternModal() {
    const modal = document.getElementById('pattern-modal');
    const form = document.getElementById('pattern-form');
    const addBtn = document.getElementById('add-pattern-btn');
    const closeBtn = document.getElementById('close-modal');
    const cancelBtn = document.getElementById('cancel-pattern');

    addBtn.addEventListener('click', () => openPatternModal());
    closeBtn.addEventListener('click', () => closePatternModal());
    cancelBtn.addEventListener('click', () => closePatternModal());

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closePatternModal();
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await savePattern();
    });
}

function openPatternModal(pattern = null) {
    const modal = document.getElementById('pattern-modal');
    const title = document.getElementById('modal-title');
    const editMode = document.getElementById('pattern-edit-mode');
    const originalName = document.getElementById('pattern-original-name');
    const nameInput = document.getElementById('pattern-name');

    if (pattern) {
        title.textContent = 'Edit Pattern';
        editMode.value = 'edit';
        originalName.value = pattern.name;
        nameInput.value = pattern.name;
        nameInput.readOnly = true;
        document.getElementById('pattern-description').value = pattern.description;
        document.getElementById('pattern-severity').value = pattern.severity;
        document.getElementById('pattern-indicators').value = (pattern.indicators || []).join('\n');
        document.getElementById('pattern-examples').value = (pattern.examples || []).join('\n');
    } else {
        title.textContent = 'Add New Pattern';
        editMode.value = 'create';
        originalName.value = '';
        nameInput.value = '';
        nameInput.readOnly = false;
        document.getElementById('pattern-description').value = '';
        document.getElementById('pattern-severity').value = 'medium';
        document.getElementById('pattern-indicators').value = '';
        document.getElementById('pattern-examples').value = '';
    }

    modal.style.display = 'flex';
}

function closePatternModal() {
    document.getElementById('pattern-modal').style.display = 'none';
}

async function savePattern() {
    const editMode = document.getElementById('pattern-edit-mode').value;
    const originalName = document.getElementById('pattern-original-name').value;

    const name = document.getElementById('pattern-name').value.trim();
    const description = document.getElementById('pattern-description').value.trim();
    const severity = document.getElementById('pattern-severity').value;
    const indicators = document.getElementById('pattern-indicators').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);
    const examples = document.getElementById('pattern-examples').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);

    if (!name || !description) {
        showToast('Name and description are required', 'warning');
        return;
    }

    try {
        if (editMode === 'edit') {
            await api.put(`/api/patterns/${encodeURIComponent(originalName)}`, {
                description,
                severity,
                indicators,
                examples,
            });
            showToast(`Pattern "${name}" updated`, 'success');
        } else {
            await api.post('/api/patterns', {
                name,
                description,
                severity,
                indicators,
                examples,
            });
            showToast(`Pattern "${name}" created`, 'success');
        }
        closePatternModal();
        loadPatterns();
    } catch (error) {
        showToast(`Failed to save: ${error.message}`, 'error');
    }
}

function initPatternActions() {
    // Export
    document.getElementById('export-patterns-btn').addEventListener('click', async () => {
        try {
            const response = await fetch('/api/patterns/export');
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'scam_patterns.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Patterns exported successfully', 'success');
        } catch (error) {
            showToast(`Export failed: ${error.message}`, 'error');
        }
    });

    // Import
    const importFile = document.getElementById('import-file');
    document.getElementById('import-patterns-btn').addEventListener('click', () => {
        importFile.click();
    });

    importFile.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const replace = confirm('Replace existing patterns? Click OK to replace all, Cancel to add new ones only.');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`/api/patterns/import?replace=${replace}`, {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Import failed');
            }

            const result = await response.json();
            showToast(result.message, 'success');
            loadPatterns();
        } catch (error) {
            showToast(`Import failed: ${error.message}`, 'error');
        }

        // Reset file input
        importFile.value = '';
    });

    // Reset
    document.getElementById('reset-patterns-btn').addEventListener('click', async () => {
        if (!confirm('Reset all patterns to defaults? This will remove any custom patterns.')) {
            return;
        }

        try {
            await api.post('/api/patterns/reset', {});
            showToast('Patterns reset to defaults', 'success');
            loadPatterns();
        } catch (error) {
            showToast(`Reset failed: ${error.message}`, 'error');
        }
    });
}

// Configuration
async function loadConfig() {
    try {
        const config = await api.get('/api/config');
        document.getElementById('config-base-url').value = config.base_url || '';
        document.getElementById('config-api-key').value = '';
        document.getElementById('config-api-key').placeholder = config.api_key || 'Not configured';
        document.getElementById('config-model').value = config.model || '';
        document.getElementById('config-temperature').value = config.temperature || 0.1;
        document.getElementById('config-max-tokens').value = config.max_tokens || 2048;
    } catch (error) {
        showToast(`Failed to load config: ${error.message}`, 'error');
    }
}

function initConfig() {
    const form = document.getElementById('config-form');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const update = {};

        const baseUrl = document.getElementById('config-base-url').value.trim();
        if (baseUrl) update.base_url = baseUrl;

        const apiKey = document.getElementById('config-api-key').value.trim();
        if (apiKey) update.api_key = apiKey;

        const model = document.getElementById('config-model').value.trim();
        if (model) update.model = model;

        const temp = document.getElementById('config-temperature').value;
        if (temp) update.temperature = parseFloat(temp);

        const tokens = document.getElementById('config-max-tokens').value;
        if (tokens) update.max_tokens = parseInt(tokens);

        try {
            await api.put('/api/config', update);
            showToast('Configuration saved', 'success');
            loadConfig();
        } catch (error) {
            showToast(`Failed to save config: ${error.message}`, 'error');
        }
    });
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initAnalyze();
    initPatternModal();
    initPatternActions();
    initConfig();

    // Load patterns on first visit
    loadPatterns();
});

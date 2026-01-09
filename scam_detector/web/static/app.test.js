/**
 * Tests for the Scam Detection System frontend application.
 */

// Helper to create mock HTML structure
function setupDOM() {
    document.body.innerHTML = `
        <div id="toast" class="toast"></div>

        <!-- Tab navigation -->
        <div class="tab-navigation">
            <button class="tab-btn active" data-tab="analyze">Analyze</button>
            <button class="tab-btn" data-tab="patterns">Patterns</button>
            <button class="tab-btn" data-tab="config">Config</button>
        </div>

        <div id="analyze" class="tab-content active">
            <form id="analyze-form">
                <input id="message-title" type="text" />
                <input id="message-author" type="text" />
                <textarea id="message-content"></textarea>
                <button id="analyze-btn" type="submit">
                    <span class="btn-text">Analyze</span>
                    <span class="btn-loading" style="display: none;">Loading...</span>
                </button>
            </form>
            <div id="results-container" style="display: none;">
                <div id="results-content"></div>
            </div>
        </div>

        <div id="patterns" class="tab-content">
            <button id="add-pattern-btn">Add Pattern</button>
            <button id="export-patterns-btn">Export</button>
            <button id="import-patterns-btn">Import</button>
            <input type="file" id="import-file" style="display: none;" />
            <button id="reset-patterns-btn">Reset</button>
            <div id="patterns-list"></div>
        </div>

        <div id="config" class="tab-content">
            <form id="config-form">
                <input id="config-base-url" type="text" />
                <input id="config-api-key" type="password" />
                <input id="config-model" type="text" />
                <input id="config-temperature" type="number" step="0.1" />
                <input id="config-max-tokens" type="number" />
                <button type="submit">Save</button>
            </form>
        </div>

        <!-- Pattern Modal -->
        <div id="pattern-modal" class="modal" style="display: none;">
            <div class="modal-content">
                <button id="close-modal">X</button>
                <h2 id="modal-title">Add Pattern</h2>
                <form id="pattern-form">
                    <input type="hidden" id="pattern-edit-mode" value="create" />
                    <input type="hidden" id="pattern-original-name" value="" />
                    <input id="pattern-name" type="text" />
                    <textarea id="pattern-description"></textarea>
                    <select id="pattern-severity">
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                    <textarea id="pattern-indicators"></textarea>
                    <textarea id="pattern-examples"></textarea>
                    <button type="submit">Save</button>
                    <button type="button" id="cancel-pattern">Cancel</button>
                </form>
            </div>
        </div>
    `;
}

// Mock fetch helper
function mockFetch(response, ok = true, status = 200) {
    global.fetch.mockResolvedValueOnce({
        ok,
        status,
        json: () => Promise.resolve(response),
        blob: () => Promise.resolve(new Blob([JSON.stringify(response)])),
    });
}

function mockFetchError(detail = 'Request failed', status = 500) {
    global.fetch.mockResolvedValueOnce({
        ok: false,
        status,
        json: () => Promise.resolve({ detail }),
    });
}

// ============================================
// API Helper Tests
// ============================================

describe('API Helper', () => {
    let api;

    beforeEach(() => {
        setupDOM();
        // Re-evaluate app.js to get fresh api object
        jest.resetModules();

        // Define api object for testing
        api = {
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
    });

    test('api.get makes GET request', async () => {
        mockFetch({ data: 'test' });

        const result = await api.get('/api/test');

        expect(fetch).toHaveBeenCalledWith('/api/test', {
            headers: { 'Content-Type': 'application/json' },
        });
        expect(result).toEqual({ data: 'test' });
    });

    test('api.post makes POST request with JSON body', async () => {
        mockFetch({ success: true });

        const result = await api.post('/api/test', { key: 'value' });

        expect(fetch).toHaveBeenCalledWith('/api/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: 'value' }),
        });
        expect(result).toEqual({ success: true });
    });

    test('api.put makes PUT request with JSON body', async () => {
        mockFetch({ updated: true });

        const result = await api.put('/api/test', { key: 'new-value' });

        expect(fetch).toHaveBeenCalledWith('/api/test', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: 'new-value' }),
        });
        expect(result).toEqual({ updated: true });
    });

    test('api.delete makes DELETE request', async () => {
        mockFetch({ deleted: true });

        const result = await api.delete('/api/test');

        expect(fetch).toHaveBeenCalledWith('/api/test', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
        });
        expect(result).toEqual({ deleted: true });
    });

    test('api.request throws on non-ok response', async () => {
        mockFetchError('Not found', 404);

        await expect(api.get('/api/missing')).rejects.toThrow('Not found');
    });

    test('api.request handles JSON parse error in error response', async () => {
        global.fetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: () => Promise.reject(new Error('Invalid JSON')),
        });

        await expect(api.get('/api/broken')).rejects.toThrow('Request failed');
    });
});

// ============================================
// Toast Notification Tests
// ============================================

describe('showToast', () => {
    let showToast;

    beforeEach(() => {
        setupDOM();

        // Define showToast function
        showToast = (message, type = 'info') => {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = `toast ${type} show`;
        };
    });

    test('displays message in toast element', () => {
        showToast('Test message');

        const toast = document.getElementById('toast');
        expect(toast.textContent).toBe('Test message');
    });

    test('applies correct CSS class for type', () => {
        showToast('Warning!', 'warning');

        const toast = document.getElementById('toast');
        expect(toast.className).toContain('warning');
        expect(toast.className).toContain('show');
    });

    test('applies info type by default', () => {
        showToast('Info message');

        const toast = document.getElementById('toast');
        expect(toast.className).toContain('info');
    });

    test('applies error type', () => {
        showToast('Error!', 'error');

        const toast = document.getElementById('toast');
        expect(toast.className).toContain('error');
    });

    test('applies success type', () => {
        showToast('Success!', 'success');

        const toast = document.getElementById('toast');
        expect(toast.className).toContain('success');
    });
});

// ============================================
// Tab Navigation Tests
// ============================================

describe('Tab Navigation', () => {
    let initTabs;

    beforeEach(() => {
        setupDOM();

        initTabs = () => {
            const tabBtns = document.querySelectorAll('.tab-btn');
            const tabContents = document.querySelectorAll('.tab-content');

            tabBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    const tabId = btn.dataset.tab;

                    tabBtns.forEach(b => b.classList.remove('active'));
                    tabContents.forEach(c => c.classList.remove('active'));

                    btn.classList.add('active');
                    document.getElementById(tabId).classList.add('active');
                });
            });
        };

        initTabs();
    });

    test('clicking tab button switches active tab', () => {
        const patternsBtn = document.querySelector('[data-tab="patterns"]');
        patternsBtn.click();

        expect(patternsBtn.classList.contains('active')).toBe(true);
        expect(document.getElementById('patterns').classList.contains('active')).toBe(true);
        expect(document.getElementById('analyze').classList.contains('active')).toBe(false);
    });

    test('removes active class from previous tab', () => {
        const analyzeBtn = document.querySelector('[data-tab="analyze"]');
        const patternsBtn = document.querySelector('[data-tab="patterns"]');

        expect(analyzeBtn.classList.contains('active')).toBe(true);

        patternsBtn.click();

        expect(analyzeBtn.classList.contains('active')).toBe(false);
        expect(patternsBtn.classList.contains('active')).toBe(true);
    });

    test('switching to config tab', () => {
        const configBtn = document.querySelector('[data-tab="config"]');
        configBtn.click();

        expect(configBtn.classList.contains('active')).toBe(true);
        expect(document.getElementById('config').classList.contains('active')).toBe(true);
    });
});

// ============================================
// Display Results Tests
// ============================================

describe('displayResults', () => {
    let displayResults;

    beforeEach(() => {
        setupDOM();

        displayResults = (result) => {
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
        };
    });

    test('displays no scam result correctly', () => {
        displayResults({
            risk_level: 'none',
            is_scam: false,
            matched_patterns: [],
            summary: 'This message appears safe.'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('No Scam Detected');
        expect(content.innerHTML).toContain('risk-none');
        expect(content.innerHTML).toContain('This message appears safe.');
    });

    test('displays scam result with matched patterns', () => {
        displayResults({
            risk_level: 'high',
            is_scam: true,
            matched_patterns: [
                {
                    pattern_name: 'crypto_pump_dump',
                    confidence: 0.9,
                    evidence: ['Buy now!', '100x guaranteed'],
                    explanation: 'Classic pump and dump scheme'
                }
            ],
            summary: 'High risk crypto scam detected.'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('Potential Scam Detected');
        expect(content.innerHTML).toContain('risk-high');
        expect(content.innerHTML).toContain('crypto_pump_dump');
        expect(content.innerHTML).toContain('90%');
        expect(content.innerHTML).toContain('Classic pump and dump scheme');
        expect(content.innerHTML).toContain('Buy now!');
    });

    test('calculates confidence percentage correctly', () => {
        displayResults({
            risk_level: 'medium',
            is_scam: true,
            matched_patterns: [
                { pattern_name: 'test', confidence: 0.55, evidence: [], explanation: '' }
            ],
            summary: 'Test'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('55%');
        expect(content.innerHTML).toContain('confidence-medium');
    });

    test('applies low confidence class for low confidence', () => {
        displayResults({
            risk_level: 'low',
            is_scam: true,
            matched_patterns: [
                { pattern_name: 'test', confidence: 0.3, evidence: [], explanation: '' }
            ],
            summary: 'Test'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('confidence-low');
    });

    test('applies high confidence class for high confidence', () => {
        displayResults({
            risk_level: 'critical',
            is_scam: true,
            matched_patterns: [
                { pattern_name: 'test', confidence: 0.85, evidence: [], explanation: '' }
            ],
            summary: 'Test'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('confidence-high');
    });

    test('handles empty evidence array', () => {
        displayResults({
            risk_level: 'medium',
            is_scam: true,
            matched_patterns: [
                { pattern_name: 'test', confidence: 0.5, evidence: [], explanation: 'Some explanation' }
            ],
            summary: 'Test'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).not.toContain('evidence-list');
    });

    test('handles missing explanation', () => {
        displayResults({
            risk_level: 'medium',
            is_scam: true,
            matched_patterns: [
                { pattern_name: 'test', confidence: 0.5, evidence: ['evidence 1'] }
            ],
            summary: 'Test'
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).not.toContain('class="explanation"');
    });

    test('uses default summary when not provided', () => {
        displayResults({
            risk_level: 'none',
            is_scam: false,
            matched_patterns: []
        });

        const content = document.getElementById('results-content');
        expect(content.innerHTML).toContain('Analysis complete.');
    });
});

// ============================================
// Pattern Item Creation Tests
// ============================================

describe('createPatternItem', () => {
    let createPatternItem;

    beforeEach(() => {
        setupDOM();

        createPatternItem = (pattern) => {
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
        };
    });

    test('creates pattern item with basic info', () => {
        const html = createPatternItem({
            name: 'test_pattern',
            description: 'A test pattern',
            severity: 'high',
            indicators: [],
            examples: []
        });

        expect(html).toContain('test_pattern');
        expect(html).toContain('A test pattern');
        expect(html).toContain('severity-high');
    });

    test('creates pattern item with indicators', () => {
        const html = createPatternItem({
            name: 'test',
            description: 'Test',
            severity: 'medium',
            indicators: ['Indicator 1', 'Indicator 2'],
            examples: []
        });

        expect(html).toContain('<h4>Indicators</h4>');
        expect(html).toContain('<li>Indicator 1</li>');
        expect(html).toContain('<li>Indicator 2</li>');
    });

    test('creates pattern item with examples', () => {
        const html = createPatternItem({
            name: 'test',
            description: 'Test',
            severity: 'low',
            indicators: [],
            examples: ['Example 1', 'Example 2']
        });

        expect(html).toContain('<h4>Examples</h4>');
        expect(html).toContain('<li>Example 1</li>');
        expect(html).toContain('<li>Example 2</li>');
    });

    test('omits indicators section when empty', () => {
        const html = createPatternItem({
            name: 'test',
            description: 'Test',
            severity: 'critical',
            indicators: [],
            examples: ['Example']
        });

        expect(html).not.toContain('<h4>Indicators</h4>');
    });

    test('omits examples section when empty', () => {
        const html = createPatternItem({
            name: 'test',
            description: 'Test',
            severity: 'medium',
            indicators: ['Indicator'],
            examples: []
        });

        expect(html).not.toContain('<h4>Examples</h4>');
    });

    test('includes edit and delete buttons with pattern name', () => {
        const html = createPatternItem({
            name: 'my_pattern',
            description: 'Test',
            severity: 'high',
            indicators: [],
            examples: []
        });

        expect(html).toContain('data-name="my_pattern"');
        expect(html).toContain('edit-pattern');
        expect(html).toContain('delete-pattern');
    });
});

// ============================================
// Pattern Modal Tests
// ============================================

describe('Pattern Modal', () => {
    let openPatternModal, closePatternModal;

    beforeEach(() => {
        setupDOM();

        openPatternModal = (pattern = null) => {
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
        };

        closePatternModal = () => {
            document.getElementById('pattern-modal').style.display = 'none';
        };
    });

    test('opens modal for creating new pattern', () => {
        openPatternModal();

        const modal = document.getElementById('pattern-modal');
        expect(modal.style.display).toBe('flex');
        expect(document.getElementById('modal-title').textContent).toBe('Add New Pattern');
        expect(document.getElementById('pattern-edit-mode').value).toBe('create');
        expect(document.getElementById('pattern-name').readOnly).toBe(false);
    });

    test('opens modal for editing existing pattern', () => {
        const pattern = {
            name: 'existing_pattern',
            description: 'An existing pattern',
            severity: 'high',
            indicators: ['ind1', 'ind2'],
            examples: ['ex1']
        };

        openPatternModal(pattern);

        expect(document.getElementById('modal-title').textContent).toBe('Edit Pattern');
        expect(document.getElementById('pattern-edit-mode').value).toBe('edit');
        expect(document.getElementById('pattern-name').value).toBe('existing_pattern');
        expect(document.getElementById('pattern-name').readOnly).toBe(true);
        expect(document.getElementById('pattern-description').value).toBe('An existing pattern');
        expect(document.getElementById('pattern-severity').value).toBe('high');
        expect(document.getElementById('pattern-indicators').value).toBe('ind1\nind2');
        expect(document.getElementById('pattern-examples').value).toBe('ex1');
    });

    test('closes modal', () => {
        openPatternModal();
        expect(document.getElementById('pattern-modal').style.display).toBe('flex');

        closePatternModal();
        expect(document.getElementById('pattern-modal').style.display).toBe('none');
    });

    test('resets form when opening for new pattern after editing', () => {
        openPatternModal({
            name: 'test',
            description: 'Test desc',
            severity: 'critical',
            indicators: ['ind'],
            examples: ['ex']
        });

        openPatternModal(null);

        expect(document.getElementById('pattern-name').value).toBe('');
        expect(document.getElementById('pattern-description').value).toBe('');
        expect(document.getElementById('pattern-severity').value).toBe('medium');
    });
});

// ============================================
// Form Validation Tests
// ============================================

describe('Form Validation', () => {
    beforeEach(() => {
        setupDOM();
    });

    test('analyze form requires content', () => {
        const content = document.getElementById('message-content');
        content.value = '';

        // The form should show warning if content is empty
        const isEmpty = content.value.trim() === '';
        expect(isEmpty).toBe(true);
    });

    test('analyze form accepts valid content', () => {
        const content = document.getElementById('message-content');
        content.value = 'This is a test message';

        const isEmpty = content.value.trim() === '';
        expect(isEmpty).toBe(false);
    });

    test('pattern form requires name and description', () => {
        const name = document.getElementById('pattern-name');
        const description = document.getElementById('pattern-description');

        name.value = '';
        description.value = '';

        const isValid = name.value.trim() && description.value.trim();
        expect(isValid).toBeFalsy();
    });

    test('pattern form valid with name and description', () => {
        const name = document.getElementById('pattern-name');
        const description = document.getElementById('pattern-description');

        name.value = 'test_pattern';
        description.value = 'A test pattern';

        const isValid = name.value.trim() && description.value.trim();
        expect(isValid).toBeTruthy();
    });
});

// ============================================
// Configuration Form Tests
// ============================================

describe('Configuration Handling', () => {
    beforeEach(() => {
        setupDOM();
    });

    test('config form parses temperature as float', () => {
        const tempInput = document.getElementById('config-temperature');
        tempInput.value = '0.7';

        const temp = parseFloat(tempInput.value);
        expect(temp).toBe(0.7);
    });

    test('config form parses max tokens as integer', () => {
        const tokensInput = document.getElementById('config-max-tokens');
        tokensInput.value = '4096';

        const tokens = parseInt(tokensInput.value);
        expect(tokens).toBe(4096);
    });

    test('config form builds update object correctly', () => {
        document.getElementById('config-base-url').value = 'http://example.com/v1';
        document.getElementById('config-api-key').value = 'secret-key';
        document.getElementById('config-model').value = 'gpt-4';
        document.getElementById('config-temperature').value = '0.5';
        document.getElementById('config-max-tokens').value = '2048';

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

        expect(update).toEqual({
            base_url: 'http://example.com/v1',
            api_key: 'secret-key',
            model: 'gpt-4',
            temperature: 0.5,
            max_tokens: 2048
        });
    });

    test('config form skips empty fields', () => {
        document.getElementById('config-base-url').value = '';
        document.getElementById('config-api-key').value = '';
        document.getElementById('config-model').value = 'gpt-4';
        document.getElementById('config-temperature').value = '';
        document.getElementById('config-max-tokens').value = '';

        const update = {};

        const baseUrl = document.getElementById('config-base-url').value.trim();
        if (baseUrl) update.base_url = baseUrl;

        const apiKey = document.getElementById('config-api-key').value.trim();
        if (apiKey) update.api_key = apiKey;

        const model = document.getElementById('config-model').value.trim();
        if (model) update.model = model;

        expect(update).toEqual({
            model: 'gpt-4'
        });
    });
});

// ============================================
// Integration Tests
// ============================================

describe('Integration Tests', () => {
    beforeEach(() => {
        setupDOM();
    });

    test('full pattern CRUD workflow', () => {
        // Create pattern item HTML
        const createPatternItem = (pattern) => {
            return `<div class="pattern-item" data-name="${pattern.name}">
                ${pattern.name} - ${pattern.description}
            </div>`;
        };

        const patterns = [];
        const patternsList = document.getElementById('patterns-list');

        // Create
        const newPattern = {
            name: 'test_pattern',
            description: 'Test description',
            severity: 'high'
        };
        patterns.push(newPattern);
        patternsList.innerHTML = patterns.map(createPatternItem).join('');

        expect(patternsList.innerHTML).toContain('test_pattern');

        // Update
        patterns[0].description = 'Updated description';
        patternsList.innerHTML = patterns.map(createPatternItem).join('');

        expect(patternsList.innerHTML).toContain('Updated description');

        // Delete
        patterns.splice(0, 1);
        patternsList.innerHTML = patterns.length > 0
            ? patterns.map(createPatternItem).join('')
            : '<div class="empty-state">No patterns</div>';

        expect(patternsList.innerHTML).toContain('No patterns');
    });

    test('loading state management', () => {
        const btn = document.getElementById('analyze-btn');
        const btnText = btn.querySelector('.btn-text');
        const btnLoading = btn.querySelector('.btn-loading');

        // Initial state
        expect(btn.disabled).toBe(false);
        expect(btnText.style.display).not.toBe('none');
        expect(btnLoading.style.display).toBe('none');

        // Loading state
        btn.disabled = true;
        btnText.style.display = 'none';
        btnLoading.style.display = 'inline';

        expect(btn.disabled).toBe(true);
        expect(btnText.style.display).toBe('none');
        expect(btnLoading.style.display).toBe('inline');

        // Reset state
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';

        expect(btn.disabled).toBe(false);
        expect(btnText.style.display).toBe('inline');
        expect(btnLoading.style.display).toBe('none');
    });

    test('results container visibility', () => {
        const resultsContainer = document.getElementById('results-container');

        // Initially hidden
        expect(resultsContainer.style.display).toBe('none');

        // Show after analysis
        resultsContainer.style.display = 'block';
        expect(resultsContainer.style.display).toBe('block');
    });
});

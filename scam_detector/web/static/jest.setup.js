/**
 * Jest setup file for frontend tests.
 * Sets up DOM environment and mocks.
 */

// Mock fetch globally
global.fetch = jest.fn();

// Mock URL.createObjectURL and revokeObjectURL
global.URL.createObjectURL = jest.fn(() => 'blob:mock-url');
global.URL.revokeObjectURL = jest.fn();

// Mock scrollIntoView
Element.prototype.scrollIntoView = jest.fn();

// Mock confirm dialog
global.confirm = jest.fn(() => true);

// Helper to reset mocks between tests
beforeEach(() => {
    jest.clearAllMocks();
    document.body.innerHTML = '';
});

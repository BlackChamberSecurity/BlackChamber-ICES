/**
 * BlackChamber ICES — API Client
 *
 * Wraps fetch() with JWT token management and auto-redirect on 401.
 */

const API_BASE = '/api';

export function getToken() {
    return localStorage.getItem('ices_token');
}

export function setToken(token) {
    localStorage.setItem('ices_token', token);
}

export function clearToken() {
    localStorage.removeItem('ices_token');
}

export function isAuthenticated() {
    return !!getToken();
}

/**
 * Authenticated fetch wrapper.
 * Automatically attaches Bearer token and handles 401 redirects.
 */
export async function apiFetch(path, options = {}) {
    const token = getToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
    };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (res.status === 401) {
        clearToken();
        window.location.href = '/login';
        throw new Error('Unauthorized');
    }

    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
    }

    return res.json();
}

/**
 * Login and store the JWT.
 */
export async function login(username, password) {
    const data = await apiFetch('/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
    });
    setToken(data.token);
    return data;
}

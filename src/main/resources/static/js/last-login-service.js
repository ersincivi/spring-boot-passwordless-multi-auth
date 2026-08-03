/**
 * Last Login Service
 * Manages last login account information in localStorage and cookies
 * Used for "Continue with this account" feature
 */

const LastLoginService = {
    STORAGE_KEY: 'lastLoginInfo',
    COOKIE_NAME: 'lastLoginEmail',
    COOKIE_DAYS: 30,

    /**
     * Save last login information
     * @param {Object} loginInfo - Login information
     * @param {string} loginInfo.email - User email
     * @param {string} loginInfo.userName - User display name
     * @param {string} loginInfo.loginMethod - Login method (email, google, github)
     * @param {string} loginInfo.profileImageUrl - User profile image URL (optional)
     */
    saveLastLogin(loginInfo) {
        try {
            const data = {
                email: loginInfo.email,
                userName: loginInfo.userName,
                loginMethod: loginInfo.loginMethod,
                profileImageUrl: loginInfo.profileImageUrl || null,
                lastLoginAt: new Date().toISOString()
            };

            // Save to localStorage
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(data));

            // Save email to cookie for cross-session persistence
            this.setCookie(this.COOKIE_NAME, loginInfo.email, this.COOKIE_DAYS);

        } catch (error) {
            console.error('Error saving last login info:', error);
        }
    },

    /**
     * Get last login information
     * @returns {Object|null} Last login information or null if not found
     */
    getLastLogin() {
        try {
            // Try localStorage first
            const data = localStorage.getItem(this.STORAGE_KEY);
            if (data) {
                return JSON.parse(data);
            }

            // Fallback to cookie
            const email = this.getCookie(this.COOKIE_NAME);
            if (email) {
                return {
                    email: email,
                    userName: null,
                    loginMethod: 'email',
                    profileImageUrl: null,
                    lastLoginAt: null
                };
            }

            return null;
        } catch (error) {
            return null;
        }
    },

    /**
     * Clear last login information
     */
    clearLastLogin() {
        try {
            localStorage.removeItem(this.STORAGE_KEY);
            this.deleteCookie(this.COOKIE_NAME);
        } catch (error) {
        }
    },

    /**
     * Check if there is last login information
     * @returns {boolean} True if last login exists
     */
    hasLastLogin() {
        return this.getLastLogin() !== null;
    },

    /**
     * Get login method display name
     * @param {string} method - Login method (email, google, github)
     * @returns {string} Display name
     */
    getMethodDisplayName(method) {
        const methodNames = {
            'email': 'Email',
            'google': 'Google',
            'github': 'GitHub'
        };
        return methodNames[method] || method;
    },

    /**
     * Get login method icon class
     * @param {string} method - Login method
     * @returns {string} Icon class name
     */
    getMethodIcon(method) {
        const icons = {
            'email': 'fa-envelope',
            'google': 'fa-google',
            'github': 'fa-github'
        };
        return icons[method] || 'fa-user';
    },

    /**
     * Set cookie
     * @param {string} name - Cookie name
     * @param {string} value - Cookie value
     * @param {number} days - Expiration in days
     */
    setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${encodeURIComponent(value)};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
    },

    /**
     * Get cookie
     * @param {string} name - Cookie name
     * @returns {string|null} Cookie value or null
     */
    getCookie(name) {
        const nameEQ = name + "=";
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i].trim();
            if (cookie.indexOf(nameEQ) === 0) {
                return decodeURIComponent(cookie.substring(nameEQ.length));
            }
        }
        return null;
    },

    /**
     * Delete cookie
     * @param {string} name - Cookie name
     */
    deleteCookie(name) {
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;`;
    },

    /**
     * Fetch last login info from server
     * @param {string} email - User email (optional)
     * @returns {Promise<Object|null>} Server-side last login info or null
     */
    async fetchFromServer(email = null) {
        try {
            const url = email 
                ? `/api/last-login?email=${encodeURIComponent(email)}`
                : '/api/last-login/current';
            
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin'
            });

            if (response.ok) {
                const data = await response.json();
                if (data) {
                    // Sync with localStorage
                    console.log("GELEN data: ", data);
                    this.saveLastLogin(data);
                    return data;
                }
            }
            return null;
        } catch (error) {
            return null;
        }
    }
};

// Make available globally
window.LastLoginService = LastLoginService;

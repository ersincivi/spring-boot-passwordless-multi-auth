// Simple Login Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize last login detection first
    initializeLastAccountLogin();
    // Initialize basic login page functionality
    initializeEmailMagicLinkFlow();
    initializeAnimations();
    initializeLanguageSwitcher();
    initializeRememberMe();
});

// Last Account Smart Login
function initializeLastAccountLogin() {
    if (!window.LastLoginService) {
        return;
    }

    const lastAccountSection = document.getElementById('lastAccountSection');
    const regularLoginSection = document.getElementById('regularLoginSection');
    const continueLastAccountBtn = document.getElementById('continueLastAccountBtn');
    const useDifferentMethodBtn = document.getElementById('useDifferentMethodBtn');

    // Check if there's a last login
    const lastLogin = LastLoginService.getLastLogin();

    if (lastLogin && lastLogin.email) {
        // Show last account section, hide regular login
        displayLastAccount(lastLogin);
        lastAccountSection.style.display = 'block';
        regularLoginSection.style.display = 'none';

        // Handle "Continue with this account" button
        if (continueLastAccountBtn) {
            continueLastAccountBtn.addEventListener('click', function() {
                handleLastAccountLogin(lastLogin);
            });
        }

        // Handle "Use a different login method" button
        if (useDifferentMethodBtn) {
            useDifferentMethodBtn.addEventListener('click', function() {
                lastAccountSection.style.display = 'none';
                regularLoginSection.style.display = 'block';
                // Pre-fill email if method is email
                if (lastLogin.loginMethod === 'email') {
                    const emailInput = document.getElementById('email-input');
                    if (emailInput) {
                        emailInput.value = lastLogin.email ;
                    }
                }
            });
        }

        // Handle "Remove account" button
        const removeAccountBtn = document.getElementById('removeAccountBtn');
        if (removeAccountBtn) {
            removeAccountBtn.addEventListener('click', function() {
                // Clear localStorage
                localStorage.clear();
                
                // Clear all cookies
                document.cookie.split(';').forEach(function(cookie) {
                    const [name] = cookie.split('=');
                    document.cookie = name.trim() + '=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;';
                    document.cookie = name.trim() + '=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;domain=' + window.location.hostname + ';';
                });
                
                // Clear LastLoginService data
                if (window.LastLoginService) {
                    LastLoginService.clearLastLogin();
                }
                
                // Hide last account section and show regular login
                lastAccountSection.style.display = 'none';
                regularLoginSection.style.display = 'block';
                
                // Clear email input
                const emailInput = document.getElementById('email-input');
                if (emailInput) {
                    emailInput.value = '';
                }
            });
        }
    } else {
        // No last login, show regular login
        lastAccountSection.style.display = 'none';
        regularLoginSection.style.display = 'block';
    }
}

function displayLastAccount(lastLogin) {
    const avatarDiv = document.getElementById('lastAccountAvatar');
    const nameDiv = document.getElementById('lastAccountName');
    const emailDiv = document.getElementById('lastAccountEmail');
    const methodDiv = document.getElementById('lastAccountMethod');

    // Set avatar (profile image or fallback to initials)
    if (avatarDiv) {
        if (lastLogin.profileImageUrl != null) {
            avatarDiv.innerHTML = `<img src="${lastLogin.profileImageUrl}" alt="Profile" />`;
        } else {
            // Show email initial
            const initial = lastLogin.email.charAt(0).toUpperCase();
            avatarDiv.innerHTML = `<div style="font-size: 2.5rem; font-weight: 600;">${initial}</div>`;
        }
    }

    // Set name (or fallback to email)
    if (nameDiv) {
        nameDiv.textContent = lastLogin.userName  || lastLogin.email.split('@')[0];
    }

    // Set email
    if (emailDiv) {
        emailDiv.textContent = lastLogin.email ;
    }

    // Set login method with icon
    if (methodDiv) {
        const methodName = LastLoginService.getMethodDisplayName(lastLogin.loginMethod);
        const methodIcon = getMethodIconSVG(lastLogin.loginMethod);
        methodDiv.innerHTML = `${methodIcon} <span>${methodName}</span>`;
    }
}

function getMethodIconSVG(method) {
    const icons = {
        'email': '📧',
        'google': '<svg width="16" height="16" viewBox="0 0 24 24" style="display: inline-block; vertical-align: middle;"><path fill="white" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="white" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="white" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="white" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>',
        'github': '<svg width="16" height="16" viewBox="0 0 24 24" style="display: inline-block; vertical-align: middle;"><path fill="white" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>'
    };
    return icons[method] || '👤';
}

function handleLastAccountLogin(lastLogin) {
    const method = lastLogin.loginMethod;

    if (method === 'email') {
        // For email login, show the regular MagicLink flow with pre-filled email
        const lastAccountSection = document.getElementById('lastAccountSection');
        const regularLoginSection = document.getElementById('regularLoginSection');
        const emailInput = document.getElementById('email-input');

        lastAccountSection.style.display = 'none';
        regularLoginSection.style.display = 'block';

        if (emailInput) {
            emailInput.value = lastLogin.email;
            // Auto-submit email form to send MagicLink
            const emailMagicLinkForm = document.getElementById('emailMagicLinkForm');
            if (emailMagicLinkForm) {
                emailMagicLinkForm.dispatchEvent(new Event('submit'));
            }
        }
    } else if (method === 'google') {
        // Redirect to Google OAuth
        window.location.href = '/oauth2/authorization/google';
    } else if (method === 'github') {
        // Redirect to GitHub OAuth
        window.location.href = '/oauth2/authorization/github';
    }
}

// Email MagicLink Login Flow
function initializeEmailMagicLinkFlow() {
    const emailMagicLinkForm = document.getElementById('emailMagicLinkForm');
    const emailInput = document.getElementById('email-input');
    const sendMagicLinkBtn = document.getElementById('sendMagicLinkBtn');
    const magicLinkHelp = document.getElementById('magicLinkHelp');
    const errorDisplay = document.querySelector('.alert-danger');
    
    let userEmail = '';
    
    // Send MagicLink to email
    if (emailMagicLinkForm) {
        emailMagicLinkForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = emailInput.value.trim();

            if (!email) {
                showError('Please enter your email address');
                return;
            }
            
            // Show loading state
            setButtonLoading(sendMagicLinkBtn, true);
            
            try {
                const response = await fetch('/auth/email-magiclink/send', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-XSRF-TOKEN': getCsrfToken()
                    },
                    body: JSON.stringify({ "email": email })
                });
                
                // If the server answered with a redirect to another page
                // (e.g. a pending TOTP challenge), follow it instead of
                // trying to parse the resulting HTML as JSON.
                const responseType = response.headers.get('content-type') || '';
                if (response.redirected && !responseType.includes('application/json')) {
                    window.location.href = response.url;
                    return;
                }

                if (!response.ok) {
                    // Handle error responses. Non-JSON bodies (e.g. the HTML
                    // error page served for an expired CSRF token after an
                    // app restart) must not crash the handler.
                    let errorMessage = 'Failed to send login link';
                    const contentType = response.headers.get('content-type') || '';
                    if (contentType.includes('application/json')) {
                        const errorData = await response.json();
                        errorMessage = errorData.message || errorMessage;
                    } else if (response.status === 403) {
                        errorMessage = 'Your session expired - please reload the page and try again';
                    }
                    throw new Error(errorMessage);
                }

                // Success - parse response
                const data = await response.json();
                userEmail = email;
                
                // Disable button and email input
                sendMagicLinkBtn.disabled = true;
                emailInput.disabled = true;
                
                // Show help text
                if (magicLinkHelp) {
                    magicLinkHelp.style.display = 'block';
                }
                
                showSuccess(data.message || 'Login link sent to your email. Please check your inbox.');
                
            } catch (error) {
                showError(error.message || 'Network error. Please try again.');
            } finally {
                setButtonLoading(sendMagicLinkBtn, false);
            }
        });
    }
}

// Helper functions
function setButtonLoading(button, isLoading) {
    if (!button) return;
    
    const btnText = button.querySelector('.btn-text');
    const btnLoader = button.querySelector('.btn-loader');
    
    if (isLoading) {
        if (btnText) btnText.style.display = 'none';
        if (btnLoader) {
            btnLoader.style.display = 'block';
        } else {
            // Create loader if it doesn't exist
            const loader = document.createElement('span');
            loader.className = 'btn-loader';
            loader.textContent = '...';
            button.appendChild(loader);
        }
        button.disabled = true;
    } else {
        if (btnText) btnText.style.display = 'block';
        if (btnLoader) btnLoader.style.display = 'none';
        button.disabled = false;
    }
}

function showError(message) {

    const errorDiv = document.createElement('div');
		errorDiv.className = 'alert alert-danger';
        errorDiv.style.cssText = 'margin-bottom: 20px; padding: 12px; background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; border-radius: 4px;';
        errorDiv.style.display = 'block';

    const alertIcon = document.createElement('span');
		alertIcon.className = 'alert-icon';
		alertIcon.textContent = '⚠️';
		alertIcon.style.marginRight = '10px'; 
		alertIcon.style.fontSize = '1.2em';
    
    const errorMessage = document.createElement('span');
	errorMessage.id = 'modal-error-message';
    errorMessage.textContent = message;

    errorDiv.appendChild(alertIcon);
    errorDiv.appendChild(errorMessage);
    
    const emailSection = document.getElementById('emailLoginSection');

    if (emailSection) {
        emailSection.insertBefore(errorDiv, emailSection.firstChild);
    }

    setTimeout(() => {
        errorDiv.style.transition = 'all 0.3s ease';
        errorDiv.style.opacity = '0';
        errorDiv.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
            errorDiv.remove();
        }, 300);
    }, 5000);
}

function showSuccess(message) {
     const successDiv = document.createElement('div');
		successDiv.className = 'alert alert-success';
        successDiv.style.cssText = 'margin-bottom: 20px; padding: 12px; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px;';
        successDiv.style.display = 'block';

    const alertIcon = document.createElement('span');
		alertIcon.className = 'alert-icon';
		alertIcon.textContent = '✓';
		alertIcon.style.marginRight = '10px'; 
		alertIcon.style.fontSize = '1.2em';
    
    const errorMessage = document.createElement('span');
	errorMessage.id = 'modal-error-message';
    errorMessage.textContent = message;

    successDiv.appendChild(alertIcon);
    successDiv.appendChild(errorMessage);

    const emailSection = document.getElementById('emailLoginSection');

    if (emailSection) {
        emailSection.insertBefore(successDiv, emailSection.firstChild);
    }

    setTimeout(() => {
        successDiv.style.transition = 'all 0.3s ease';
        successDiv.style.opacity = '0';
        successDiv.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
            successDiv.remove();
        }, 300);
    }, 5000);

}

function getCsrfToken() {
    // First try to get from cookie (XSRF-TOKEN)
    const cookieValue = document.cookie
        .split('; ')
        .find(row => row.startsWith('XSRF-TOKEN='))
        ?.split('=')[1];

    if (cookieValue) {
        return decodeURIComponent(cookieValue);
    }

    // Cookie read with a stricter regex
    // const match = document.cookie.match(new RegExp('(^| )XSRF-TOKEN=([^;]+)'));
    // if (match) return decodeURIComponent(match[2]);

    // Fallback to meta tag
    const tokenElement = document.querySelector('meta[name="_csrf"]');
    return tokenElement ? tokenElement.getAttribute('content') : '';
}

// Password toggle functionality removed - no longer needed for passwordless authentication

function initializeAnimations() {
    // Animate form elements on page load
    const elements = document.querySelectorAll('.form-group, .social-btn, .login-btn');
    
    elements.forEach((element, index) => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            element.style.transition = 'all 0.4s ease';
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, 100 * (index + 1));
    });
    
    // Add ripple effect to buttons
    addRippleEffect();
}

function addRippleEffect() {
    const buttons = document.querySelectorAll('.login-btn, .social-btn');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.cssText = `
                position: absolute;
                left: ${x}px;
                top: ${y}px;
                width: ${size}px;
                height: ${size}px;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.3);
                transform: scale(0);
                animation: ripple 0.6s linear;
                pointer-events: none;
                z-index: 1;
            `;
            
            this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
    
    // Add ripple animation to CSS if not already present
    if (!document.querySelector('#ripple-style')) {
        const style = document.createElement('style');
        style.id = 'ripple-style';
        style.textContent = `
            @keyframes ripple {
                to {
                    transform: scale(4);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
}

function initializeLanguageSwitcher() {
    const languageToggle = document.querySelector('.language-current');
    const languageDropdown = document.querySelector('.language-dropdown');
    
    if (!languageToggle || !languageDropdown) return;
    
    languageToggle.addEventListener('click', function(e) {
        e.preventDefault();
        const isOpen = languageDropdown.classList.contains('show');
        
        if (isOpen) {
            languageDropdown.classList.remove('show');
            languageToggle.setAttribute('aria-expanded', 'false');
        } else {
            languageDropdown.classList.add('show');
            languageToggle.setAttribute('aria-expanded', 'true');
        }
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.language-dropdown-container')) {
            languageDropdown.classList.remove('show');
            languageToggle.setAttribute('aria-expanded', 'false');
        }
    });
    
    // Handle language selection
    const languageOptions = document.querySelectorAll('.language-option');
    languageOptions.forEach(option => {
        option.addEventListener('click', function(e) {
            e.preventDefault();
            const lang = this.getAttribute('href').split('=')[1];
            window.location.href = `?lang=${lang}`;
        });
    });
}

function initializeRememberMe() {
    const rememberMeCheckbox = document.getElementById('remember-me');
    if (!rememberMeCheckbox) return;
    
    // Load saved state
    const savedState = localStorage.getItem('rememberMePreference');
    if (savedState === 'true') {
        rememberMeCheckbox.checked = true;
    }
    
    // Save state when changed
    rememberMeCheckbox.addEventListener('change', function() {
        localStorage.setItem('rememberMePreference', this.checked.toString());
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Alt + E to focus email field
    if (e.altKey && e.key.toLowerCase() === 'e') {
        e.preventDefault();
        const emailInput = document.getElementById('email-input');
        if (emailInput) {
            emailInput.focus();
        }
    }
    
    // Alt + O to focus OTP field
    if (e.altKey && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        const otpInput = document.getElementById('otp-input');
        if (otpInput && otpInput.closest('form').style.display !== 'none') {
            otpInput.focus();
        }
    }
    
    // Alt + G to click Google login
    if (e.altKey && e.key.toLowerCase() === 'g') {
        e.preventDefault();
        const googleBtn = document.querySelector('.google-btn');
        if (googleBtn) {
            googleBtn.click();
        }
    }

});

// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'all 0.3s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                alert.remove();
            }, 300);
        }, 5000);
    });
});
// Register Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize login page functionality
    initializeRegisterForm();
    initializeAnimations();
    initializeLanguageSwitcher();
    // initializePasswordValidation();
});

function initializeRegisterForm() {
	const form = document.querySelector('.register-form');
	const submitBtn = document.getElementById('submitBtn');
	const btnText = submitBtn.querySelector('.btn-text');
	const btnLoader = submitBtn.querySelector('.btn-loader');
	
	// Add input validation for all fields
	// const usernameInput = document.getElementById('username');
	const emailInput = document.getElementById('email');
	// const passwordInput = document.getElementById('password');
	// const confirmPasswordInput = document.getElementById('confirmPassword');
	
	// Check form validity on input changes
	// [usernameInput, emailInput, passwordInput, confirmPasswordInput].forEach(input => {
	// 	input.addEventListener('input', checkFormValidity);
	// });

	[emailInput].forEach(input => {
		input.addEventListener('input', checkFormValidity);
	});
	
	// Initial check
	checkFormValidity();
	
	form.addEventListener('submit', function(e) {
		// Final validation check
		if (!isFormValid()) {
			e.preventDefault();
			return false;
		}
		
		submitBtn.disabled = true;
		btnText.style.display = 'none';
		btnLoader.style.display = 'inline-block';
	});
	
	function checkFormValidity() {
		submitBtn.disabled = !isFormValid();
	}
	
	function isFormValid() {
		// Check if all fields have values
		// const isUsernameValid = usernameInput.value.trim().length >= 3;
		const isEmailValid = emailInput.value.trim().length > 0 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value);
		// const isPasswordValid = passwordInput.value.length >= 8;
		// const isConfirmPasswordValid = confirmPasswordInput.value.length >= 8 && passwordInput.value === confirmPasswordInput.value;
		
		// Check password requirements
		const requirements = document.querySelectorAll('.requirement');
		let allRequirementsMet = true;
		
		requirements.forEach(req => {
			const icon = req.querySelector('.req-icon');
			if (!icon.classList.contains('valid')) {
				allRequirementsMet = false;
			}
		});

		return isEmailValid;
		// return isUsernameValid && isEmailValid && isPasswordValid && isConfirmPasswordValid && allRequirementsMet;
	}
}

function initializeAnimations() {
    // Animate form elements on page load
    const elements = document.querySelectorAll('.form-group, .social-btn, .register-btn');
    
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
    const buttons = document.querySelectorAll('.login-btn, .social-btn, .register-btn');
    
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
    // Check if language elements exist before trying to initialize them
    const languageToggle = document.getElementById('language-toggle');
    const languageDropdown = document.getElementById('language-dropdown');
    
    // Only initialize if elements exist
    if (languageToggle && languageDropdown) {
        languageToggle.addEventListener('click', function(e) {
            e.preventDefault();
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            
            this.setAttribute('aria-expanded', !isExpanded);
            languageDropdown.classList.toggle('show');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (languageToggle && languageDropdown && 
                !languageToggle.contains(e.target) && 
                !languageDropdown.contains(e.target)) {
                languageToggle.setAttribute('aria-expanded', 'false');
                languageDropdown.classList.remove('show');
            }
        });
        
        // Keyboard navigation
        languageToggle.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.click();
            }
            if (e.key === 'Escape') {
                this.setAttribute('aria-expanded', 'false');
                languageDropdown.classList.remove('show');
            }
        });
    }
}

// function initializePasswordValidation() {
// 	const passwordInput = document.getElementById('password');
// 	const confirmPasswordInput = document.getElementById('confirmPassword');
// 	const requirements = document.querySelectorAll('.requirement');
//     const warningAnimation = document.getElementById('warning-animation');
	
// 	// Check if elements exist before adding event listeners
// 	if (!passwordInput || !requirements.length || !warningAnimation) {
// 	    return;
// 	}
	
// 	passwordInput.addEventListener('input', function() {
// 		const value = this.value;
		
// 		// Check each requirement
// 		requirements.forEach(req => {
// 			const type = req.getAttribute('data-req');
// 			const icon = req.querySelector('.req-icon');
// 			let isValid = false;
			
// 			switch(type) {
// 				case 'length':
// 					isValid = value.length >= 8;
// 					break;
// 				case 'uppercase':
// 					isValid = /[A-Z]/.test(value);
// 					break;
// 				case 'lowercase':
// 					isValid = /[a-z]/.test(value);
// 					break;
// 				case 'number':
// 					isValid = /\d/.test(value);
// 					break;
// 				case 'special':
// 					isValid = /[@$!%*?&]/.test(value);
// 					break;
// 			}
			
// 			if (isValid) {
// 				icon.textContent = '✓';
// 				icon.classList.add('valid');
// 				req.style.color = '#28a745';
// 			} else {
// 				icon.textContent = '✗';
// 				icon.classList.remove('valid');
// 				req.style.color = '#666';
// 			}
// 		});
		
// 		// Check password match
// 		checkPasswordMatch();
		
// 		// Trigger form validity check
// 		document.getElementById('submitBtn').disabled = !isFormValid();
// 	});

// 	// Add confirm password validation
// 	if (confirmPasswordInput) {
// 		confirmPasswordInput.addEventListener('input', function() {
// 			checkPasswordMatch();
// 			document.getElementById('submitBtn').disabled = !isFormValid();
// 		});
// 	}

//     // Şifre alanına odaklanıldığında uyarıları göster (animasyonlu)
//     passwordInput.addEventListener('focus', () => {
//         warningAnimation.style.maxHeight = warningAnimation.scrollHeight + 'px'; // Uyarıları aç
//     });

//     // Odak kalktığında uyarıları gizle (animasyonlu)
//     passwordInput.addEventListener('blur', () => {
//         // Only hide if not focused on requirements
//         setTimeout(() => {
//             if (!document.activeElement.closest('.password-requirements')) {
//                 warningAnimation.style.maxHeight = '0';
//             }
//         }, 100);
//     });
	
// 	// Password toggle functionality
// 	const togglePassword = document.getElementById('togglePassword');
// 	if (togglePassword) {
// 		togglePassword.addEventListener('click', function() {
//             togglePasswordVisibility(passwordInput, this);
// 		});
// 	}
	
// 	// Confirm password toggle functionality
// 	const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
// 	if (toggleConfirmPassword) {
// 		toggleConfirmPassword.addEventListener('click', function() {
//             togglePasswordVisibility(confirmPasswordInput, this);
// 		});
// 	}
// }

// function checkPasswordMatch() {
// 	const passwordInput = document.getElementById('password');
// 	const confirmPasswordInput = document.getElementById('confirmPassword');
	
// 	if (!passwordInput || !confirmPasswordInput) return;
	
// 	const password = passwordInput.value;
// 	const confirmPassword = confirmPasswordInput.value;
	
// 	// Update confirm password styling
// 	if (confirmPassword.length > 0) {
// 		if (password === confirmPassword) {
// 			confirmPasswordInput.classList.add('th-valid');
// 			confirmPasswordInput.classList.remove('th-error');
// 		} else {
// 			confirmPasswordInput.classList.add('th-error');
// 			confirmPasswordInput.classList.remove('th-valid');
// 		}
// 	} else {
// 		confirmPasswordInput.classList.remove('th-valid', 'th-error');
// 	}
// }

function togglePasswordVisibility(input, button) {
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
    button.textContent = type === 'password' ? '👁️' : '🙈';
    button.setAttribute('aria-label', type === 'password' ? 'Show password' : 'Hide password');
    
    // Maintain focus on the input field after toggling
    input.focus();
}

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

// Security event logging
window.addEventListener('error', function(e) {
	console.warn('Security: Script error detected', e.filename);
});

// Prevent basic XSS attempts
if (window.location.hash.includes('script') || window.location.search.includes('<')) {
	window.location.href = '/register';
}

// Helper function to check overall form validity
function isFormValid() {
	// const usernameInput = document.getElementById('username');
	const emailInput = document.getElementById('email');
	// const passwordInput = document.getElementById('password');
	// const confirmPasswordInput = document.getElementById('confirmPassword');
	
	// Check if all fields have values
	// const isUsernameValid = usernameInput.value.trim().length >= 3;
	const isEmailValid = emailInput.value.trim().length > 0 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value);
	// const isPasswordValid = passwordInput.value.length >= 8;
	// const isConfirmPasswordValid = confirmPasswordInput.value.length >= 8 && passwordInput.value === confirmPasswordInput.value;
	
	// Check password requirements
	const requirements = document.querySelectorAll('.requirement');
	let allRequirementsMet = true;
	
	requirements.forEach(req => {
		const icon = req.querySelector('.req-icon');
		if (!icon.classList.contains('valid')) {
			allRequirementsMet = false;
		}
	});

	return isEmailValid;
	// return isUsernameValid && isEmailValid && isPasswordValid && isConfirmPasswordValid && allRequirementsMet;
}
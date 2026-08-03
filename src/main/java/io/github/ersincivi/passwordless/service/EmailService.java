package io.github.ersincivi.passwordless.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ersincivi.passwordless.enums.EmailQueueType;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.Locale;

/**
 * Service for sending emails via SMTP (MailHog in development) Sends actual
 * emails instead of just logging them
 */
@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Autowired
    private MessageSource messageSource;

    // Configuration
    private static final String FROM_EMAIL = "noreply@example.com";

    /**
     * Generic send method for EmailQueueService compatibility (legacy)
     */
    public boolean send(String toEmail, String subject, String body, EmailQueueType type) {
        return send(toEmail, subject, body, type, Locale.ENGLISH);
    }
    
    /**
     * Enhanced send method with locale support for internationalized emails
     */
    public boolean send(String toEmail, String subject, String body, EmailQueueType type, Locale locale) {
        String enhancedBody;
        switch (type) {
            case VERIFY_OTP -> {
                enhancedBody = buildOtpEmailBody(body, locale);
                return sendEmail(toEmail, subject, enhancedBody, type);
            }
            case VERIFY_GEO -> {
                enhancedBody = buildGeoVerificationEmailBody(body, locale);
                return sendEmail(toEmail, subject, enhancedBody, type);
            }
            case GEO_ALERT -> {
                // Body format: "token|currentCountry|previousCountry|ipAddress|languageCode"
                String[] parts = body.split("\\|");
                if (parts.length >= 5) {
                    enhancedBody = buildGeoAlertEmailBody(parts[0], parts[1], parts[2], parts[3], locale);
                    return sendEmail(toEmail, subject, enhancedBody, type);
                }
                return false;
            }
            case VERIFY_MFA_EMAIL -> {
                enhancedBody = buildMfaEmailBody(body, locale);
                return sendEmail(toEmail, subject, enhancedBody, type);
            }
            case MAGICLINK_WEB -> {
                enhancedBody = buildMagicLinkWebEmailBody(body, locale);
                return sendEmail(toEmail, subject, enhancedBody, type);
            }
            case MAGICLINK_API -> {
                enhancedBody = buildMagicLinkApiEmailBody(body, locale);
                return sendEmail(toEmail, subject, enhancedBody, type);
            }
            default -> {
                return sendEmail(toEmail, "SecurePlatform - Email", body, type);
            }
        }
    }

    /**
     * Build a nicely formatted OTP email with internationalization support
     */
    private String buildOtpEmailBody(String otpCode, Locale locale) {
        // Get localized strings
        String title = messageSource.getMessage("email.otp.title", null, "Email Verification", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String thankYou = messageSource.getMessage("email.otp.thank.you", null, "Thank you for registering with Passwordless Multi-Auth! To complete your account setup, please verify your email address using the code below:", locale);
        String enterCode = messageSource.getMessage("email.otp.enter.code", null, "Please enter this 6-digit code on the verification page to activate your account.", locale);
        String securityNotice = messageSource.getMessage("email.security.notice", null, "⚠️ Security Notice:", locale);
        String codeExpiry = messageSource.getMessage("email.code.expiry", null, "This code will expire in 15 minutes", locale);
        String singleUse = messageSource.getMessage("email.code.single.use", null, "This code can only be used once", locale);
        String didntRequest = messageSource.getMessage("email.otp.didnt.request", null, "If you didn't request this verification, please ignore this email", locale);
        String neverShare = messageSource.getMessage("email.otp.never.share", null, "Never share this code with anyone", locale);
        String trouble = messageSource.getMessage("email.otp.trouble", null, "If you're having trouble with the verification process, please contact our support team.", locale);
        String welcome = messageSource.getMessage("email.otp.welcome", null, "Welcome to Passwordless Multi-Auth!", locale);
        String regards = messageSource.getMessage("email.regards", null, "Best regards,", locale);
        String team = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .otp-box {
                        background: rgba(34, 197, 94, 0.10);
                        border: 1px solid;
                        border-color: #16a34a;
                        color: black;
                        font-size: 2rem;
                        font-weight: bold;
                        letter-spacing: 0.3em;
                        padding: 20px;
                        text-align: center;
                        border-radius: 10px;
                        margin: 20px 0;
                    }
                    .warning { 
                        background-color: #fff3cd; 
                        border: 1px solid #ffeaa7; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                    }
                    .footer { 
                        text-align: center; 
                        padding: 20px; 
                        font-size: 12px; 
                        color: #666; 
                    }
                    .logo { font-size: 1.5rem; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <p>%s</p>
                        
                        <div class="otp-box">
                            %s
                        </div>
                        
                        <p>%s</p>
                        
                        <div class="warning">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s</p>
                        
                        <p>%s</p>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                thankYou,
                otpCode,
                enterCode,
                securityNotice,
                codeExpiry,
                singleUse,
                didntRequest,
                neverShare,
                trouble,
                welcome,
                regards,
                team,
                automated,
                copyright
        );
    }

    /**
     * Build a nicely formatted MFA OTP email with internationalization support
     */
    private String buildMfaEmailBody(String otpCode, Locale locale) {
        // Get localized strings
        String title = messageSource.getMessage("email.otp.title", null, "Email Verification", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String enterCode = messageSource.getMessage("email.otp.enter.code", null, "Please enter this 6-digit code on the verification page to activate your account.", locale);
        String securityNotice = messageSource.getMessage("email.security.notice", null, "⚠️ Security Notice:", locale);
        String codeExpiry = messageSource.getMessage("email.code.expiry", null, "This code will expire in 15 minutes", locale);
        String singleUse = messageSource.getMessage("email.code.single.use", null, "This code can only be used once", locale);
        String didntRequest = messageSource.getMessage("email.otp.didnt.request", null, "If you didn't request this verification, please ignore this email", locale);
        String neverShare = messageSource.getMessage("email.otp.never.share", null, "Never share this code with anyone", locale);
        String trouble = messageSource.getMessage("email.otp.trouble", null, "If you're having trouble with the verification process, please contact our support team.", locale);
        String welcome = messageSource.getMessage("email.otp.welcome", null, "Welcome to Passwordless Multi-Auth!", locale);
        String regards = messageSource.getMessage("email.regards", null, "Best regards,", locale);
        String team = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .otp-box {
                        background: rgba(34, 197, 94, 0.10);
                        border: 1px solid;
                        border-color: #16a34a;
                        color: black;
                        font-size: 2rem;
                        font-weight: bold;
                        letter-spacing: 0.3em;
                        padding: 20px;
                        text-align: center;
                        border-radius: 10px;
                        margin: 20px 0;
                    }
                    .warning { 
                        background-color: #fff3cd; 
                        border: 1px solid #ffeaa7; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                    }
                    .footer { 
                        text-align: center; 
                        padding: 20px; 
                        font-size: 12px; 
                        color: #666; 
                    }
                    .logo { font-size: 1.5rem; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <p>%s</p>
                        
                        <div class="otp-box">
                            %s
                        </div>
                        
                        <div class="warning">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s</p>
                        
                        <p>%s</p>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                enterCode,
                otpCode,
                securityNotice,
                codeExpiry,
                singleUse,
                didntRequest,
                neverShare,
                trouble,
                welcome,
                regards,
                team,
                automated,
                copyright
        );
    }

    /**
     * Build a modern HTML email template for MagicLink web authentication
     */
    private String buildMagicLinkWebEmailBody(String magicLinkUrl, Locale locale) {
        String title = messageSource.getMessage("email.magiclink.title", null, "Login to Your Account", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String clickLink = messageSource.getMessage("email.magiclink.click.link", null, "Click the button below to securely log in to your account. This link will expire in 2 minutes.", locale);
        String loginButton = messageSource.getMessage("email.magiclink.button", null, "Log In to Passwordless Multi-Auth", locale);
        String copyLink = messageSource.getMessage("email.magiclink.copy.link", null, "Or copy and paste this link into your browser:", locale);
        String securityNotice = messageSource.getMessage("email.security.notice", null, "⚠️ Security Notice:", locale);
        String linkExpiry = messageSource.getMessage("email.magiclink.expiry", null, "This link will expire in 2 minutes", locale);
        String singleUse = messageSource.getMessage("email.magiclink.single.use", null, "This link can only be used once", locale);
        String didntRequest = messageSource.getMessage("email.magiclink.didnt.request", null, "If you didn't request this login link, please ignore this email", locale);
        String neverShare = messageSource.getMessage("email.magiclink.never.share", null, "Never share this link with anyone", locale);
        String regards = messageSource.getMessage("email.regards", null, "Best regards,", locale);
        String team = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .button { 
                        display: inline-block; 
                        background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%);
                        color: white; 
                        padding: 15px 30px; 
                        text-decoration: none; 
                        border-radius: 8px; 
                        margin: 20px 0;
                        font-weight: bold;
                    }
                    .button:hover { opacity: 0.9; }
                    .warning { 
                        background-color: #fff3cd; 
                        border: 1px solid #ffeaa7; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                    }
                    .footer { 
                        text-align: center; 
                        padding: 20px; 
                        font-size: 12px; 
                        color: #666; 
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <p>%s</p>
                        
                        <div style="text-align: center;">
                            <a href="%s" class="button">%s</a>
                        </div>
                        
                        <p>%s</p>
                        <p style="word-break: break-all; background-color: #f4f4f4; padding: 10px; border-radius: 3px;">
                            %s
                        </p>
                        
                        <div class="warning">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                clickLink,
                magicLinkUrl, loginButton,
                copyLink,
                magicLinkUrl,
                securityNotice,
                linkExpiry,
                singleUse,
                didntRequest,
                neverShare,
                regards,
                team,
                automated,
                copyright
        );
    }

    /**
     * Build a modern HTML email template for MagicLink API authentication
     */
    private String buildMagicLinkApiEmailBody(String magicLinkUrl, Locale locale) {
        // API MagicLink has same email structure as WEB, but with different branding
        String title = messageSource.getMessage("email.magiclink.api.title", null, "Mobile App Login", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String clickLink = messageSource.getMessage("email.magiclink.api.click.link", null, "Click the button below to securely log in to your mobile app. This link will expire in 2 minutes.", locale);
        String loginButton = messageSource.getMessage("email.magiclink.api.button", null, "Open App", locale);
        String copyLink = messageSource.getMessage("email.magiclink.copy.link", null, "Or copy and paste this link:", locale);
        String securityNotice = messageSource.getMessage("email.security.notice", null, "⚠️ Security Notice:", locale);
        String linkExpiry = messageSource.getMessage("email.magiclink.expiry", null, "This link will expire in 2 minutes", locale);
        String singleUse = messageSource.getMessage("email.magiclink.single.use", null, "This link can only be used once", locale);
        String didntRequest = messageSource.getMessage("email.magiclink.didnt.request", null, "If you didn't request this login link, please ignore this email", locale);
        String neverShare = messageSource.getMessage("email.magiclink.never.share", null, "Never share this link with anyone", locale);
        String regards = messageSource.getMessage("email.regards", null, "Best regards,", locale);
        String team = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .button { 
                        display: inline-block; 
                        background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%);
                        color: white; 
                        padding: 15px 30px; 
                        text-decoration: none; 
                        border-radius: 8px; 
                        margin: 20px 0;
                        font-weight: bold;
                    }
                    .button:hover { opacity: 0.9; }
                    .warning { 
                        background-color: #fff3cd; 
                        border: 1px solid #ffeaa7; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                    }
                    .footer { 
                        text-align: center; 
                        padding: 20px; 
                        font-size: 12px; 
                        color: #666; 
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>📱 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <p>%s</p>
                        
                        <div style="text-align: center;">
                            <a href="%s" class="button">%s</a>
                        </div>
                        
                        <p>%s</p>
                        <p style="word-break: break-all; background-color: #f4f4f4; padding: 10px; border-radius: 3px;">
                            %s
                        </p>
                        
                        <div class="warning">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                clickLink,
                magicLinkUrl, loginButton,
                copyLink,
                magicLinkUrl,
                securityNotice,
                linkExpiry,
                singleUse,
                didntRequest,
                neverShare,
                regards,
                team,
                automated,
                copyright
        );
    }

    /**
     * Build a modern HTML email template for geographic verification with internationalization
     * Consistent with the blue theme from verify-otp.html
     */
    private String buildGeoVerificationEmailBody(String verificationCode, Locale locale) {
        // Get localized strings
        String title = messageSource.getMessage("email.geo.verification.title", null, "Geographic Login Verification", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String securityAlert = messageSource.getMessage("email.geo.security.alert", null, "Security Alert: We detected a login from an unusual location.", locale);
        String verifyMessage = messageSource.getMessage("email.geo.verify.message", null, "For your security, please verify this login attempt by entering the verification code below:", locale);
        String enterCode = messageSource.getMessage("email.geo.enter.code", null, "Please enter this 6-digit code on the geographic verification page to confirm this login attempt.", locale);
        String securityNotice = messageSource.getMessage("email.security.notice", null, "Security Notice:", locale);
        String expiry = messageSource.getMessage("email.code.expiry", null, "This code will expire in 15 minutes", locale);
        String singleUse = messageSource.getMessage("email.code.single.use", null, "This code can only be used once", locale);
        String notYou1 = messageSource.getMessage("email.geo.not.you.1", null, "If you didn't attempt to log in, please contact our security team immediately", locale);
        String notYou2 = messageSource.getMessage("email.geo.not.you.2", null, "Never share this code with anyone", locale);
        String notYou3 = messageSource.getMessage("email.geo.not.you.3", null, "If this wasn't you, change your password immediately", locale);
        String recognizeLogin = messageSource.getMessage("email.geo.recognize.login", null, "If you recognize this login attempt, complete the verification process. If you don't recognize this activity, please secure your account immediately.", locale);
        String staySecure = messageSource.getMessage("email.stay.secure", null, "Stay secure,", locale);
        String securityTeam = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Security Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated security message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);
        String needHelp = messageSource.getMessage("email.geo.need.help", null, "If you need assistance, contact our security team immediately.", locale);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .otp-box {
                        background: rgba(34, 197, 94, 0.10);
                        border: 1px solid;
                        border-color: #16a34a;
                        color: black;
                        font-size: 2rem;
                        font-weight: bold;
                        letter-spacing: 0.3em;
                        padding: 20px;
                        text-align: center;
                        border-radius: 10px;
                        margin: 20px 0;
                    }
                    .location-info {
                        background: rgba(245, 158, 11, 0.1);
                        border: 1px solid #f59e0b;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    .warning { 
                        background-color: #fff3cd; 
                        border: 1px solid #ffeaa7; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                    }
                    .security { 
                        background-color: #f8d7da; 
                        border: 1px solid #f5c6cb; 
                        padding: 15px; 
                        border-radius: 5px; 
                        margin: 20px 0; 
                        color: #721c24;
                    }
                    .footer { 
                        text-align: center; 
                        padding: 20px; 
                        font-size: 12px; 
                        color: #666; 
                    }
                    .logo { font-size: 1.5rem; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <div class="security">
                            <strong>%s</strong>
                        </div>
                        
                        <p>%s</p>
                        
                        <div class="otp-box">
                            %s
                        </div>
                        
                        <p>%s</p>
                        
                        <div class="warning">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s</p>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                securityAlert,
                verifyMessage,
                verificationCode,
                enterCode,
                securityNotice,
                expiry,
                singleUse,
                notYou1,
                notYou2,
                notYou3,
                recognizeLogin,
                staySecure,
                securityTeam,
                automated,
                copyright,
                needHelp
        );
    }

    /**
     * Build geo alert email with Yes/No action links
     * Informational alert for login from different country
     */
    private String buildGeoAlertEmailBody(String token, String currentCountry, String previousCountry, String ipAddress, Locale locale) {
        // Get localized strings
        String title = messageSource.getMessage("email.geo.alert.title", null, "Security Alert: Login from New Location", locale);
        String platform = messageSource.getMessage("email.platform.name", null, "Passwordless Multi-Auth", locale);
        String greeting = messageSource.getMessage("email.greeting", null, "Hello", locale);
        String detectedLogin = messageSource.getMessage("email.geo.alert.detected", 
            new Object[]{currentCountry, ipAddress}, 
            "We detected a login to your account from a new location: %s (IP: %s)", locale);
        String previousLocation = messageSource.getMessage("email.geo.alert.previous", 
            new Object[]{previousCountry}, 
            "Your previous login was from: %s", locale);
        String wasThisYou = messageSource.getMessage("email.geo.alert.question", null, "Was this you?", locale);
        String yesButton = messageSource.getMessage("email.geo.alert.yes", null, "Yes, it was me", locale);
        String noButton = messageSource.getMessage("email.geo.alert.no", null, "No, it's not me", locale);
        String securityRecommendations = messageSource.getMessage("email.geo.alert.recommendations", null, "Security Recommendations:", locale);
        String enableMfa = messageSource.getMessage("email.geo.alert.enable.mfa", null, "Enable two-factor authentication (2FA) for added security", locale);
        String updatePassword = messageSource.getMessage("email.geo.alert.update.password", null, "Keep your authenticator app and backup codes safe", locale);
        String reviewSessions = messageSource.getMessage("email.geo.alert.review.sessions", null, "Review active sessions in your account settings", locale);
        String contactSupport = messageSource.getMessage("email.geo.alert.contact.support", null, "Contact support if you notice any suspicious activity", locale);
        String ifNotYou = messageSource.getMessage("email.geo.alert.if.not.you", null, "If you don't recognize this activity, click 'No' above to immediately terminate the session and secure your account.", locale);
        String regards = messageSource.getMessage("email.regards", null, "Best regards,", locale);
        String securityTeam = messageSource.getMessage("email.security.team", null, "The Passwordless Multi-Auth Security Team", locale);
        String automated = messageSource.getMessage("email.automated.message", null, "This is an automated security message. Please do not reply to this email.", locale);
        String copyright = messageSource.getMessage("email.copyright", null, "© Passwordless Multi-Auth. All rights reserved.", locale);

        String confirmUrl = "http://localhost:8585/geo-alert/confirm?token=" + token;
        String denyUrl = "http://localhost:8585/geo-alert/deny?token=" + token;

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>%s - %s</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #1a3ac6 0%%, #914db9 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { padding: 30px; background-color: #f9f9f9; border-radius: 0 0 10px 10px; }
                    .location-info {
                        background: rgba(239, 68, 68, 0.1);
                        border: 1px solid #ef4444;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    .button-container {
                        text-align: center;
                        margin: 30px 0;
                    }
                    .button {
                        display: inline-block;
                        padding: 15px 30px;
                        margin: 10px;
                        text-decoration: none;
                        border-radius: 8px;
                        font-weight: bold;
                        font-size: 16px;
                    }
                    .button-yes {
                        background-color: #22c55e;
                        color: white;
                    }
                    .button-no {
                        background-color: #ef4444;
                        color: white;
                    }
                    .recommendations {
                        background-color: #fff3cd;
                        border: 1px solid #ffeaa7;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                    }
                    .footer {
                        text-align: center;
                        padding: 20px;
                        font-size: 12px;
                        color: #666;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚨 %s</h1>
                        <h2>%s</h2>
                    </div>
                    
                    <div class="content">
                        <p>%s,</p>
                        
                        <div class="location-info">
                            <p><strong>%s</strong></p>
                            <p>%s</p>
                        </div>
                        
                        <h3 style="text-align: center; color: #dc2626;">%s</h3>
                        
                        <div class="button-container">
                            <a href="%s" class="button button-yes">✅ %s</a>
                            <a href="%s" class="button button-no">❌ %s</a>
                        </div>
                        
                        <p>%s</p>
                        
                        <div class="recommendations">
                            <strong>%s</strong>
                            <ul>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                                <li>%s</li>
                            </ul>
                        </div>
                        
                        <p>%s<br>
                        %s</p>
                    </div>
                    
                    <div class="footer">
                        <p>%s</p>
                        <p>%s</p>
                    </div>
                </div>
            </body>
            </html>
            """,
                title, platform,
                platform,
                title,
                greeting,
                detectedLogin,
                previousLocation,
                wasThisYou,
                confirmUrl, yesButton,
                denyUrl, noButton,
                ifNotYou,
                securityRecommendations,
                enableMfa,
                updatePassword,
                reviewSessions,
                contactSupport,
                regards,
                securityTeam,
                automated,
                copyright
        );
    }

    /**
     * Core email sending method using JavaMailSender
     */
    private boolean sendEmail(String toEmail, String subject, String body, EmailQueueType type) {
        try {
            if (mailSender == null) {
                logger.warn("JavaMailSender not configured, falling back to logging");
                logEmail(toEmail, subject, body, type);
                return true;
            }

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(FROM_EMAIL);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(body, true); // true = HTML content

            mailSender.send(message);

            logger.info("Email sent successfully to: {}", toEmail);
            logEmail(toEmail, subject, body, type);

            return true;

        } catch (MessagingException e) {
            logger.error("Failed to send email to {}: {}", toEmail, e.getMessage());
            // Fallback to logging
            
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error sending email to {}", toEmail, e);
            return false;
        }
    }

    /**
     * Fallback method to log email content when SMTP is not available
     */
    private void logEmail(String toEmail, String subject, String body, EmailQueueType type) {
        logger.info("=== EMAIL (LOGGED) ===");
        logger.info("Type: {}", type);
        logger.info("To: {}", toEmail);
        logger.info("From: {}", FROM_EMAIL);
        logger.info("Subject: {}", subject);
        logger.info("Body: {}", body.length() > 200 ? body.substring(0, 200) + "..." : body);
        logger.info("=== END EMAIL ===");
    }
}

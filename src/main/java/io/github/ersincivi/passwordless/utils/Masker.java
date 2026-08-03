package io.github.ersincivi.passwordless.utils;

public class Masker {
    /**
     * E-posta adresini belirli bir kurala göre maskeler:
     * Shows the first 2 characters of the local part and the domain; masks the rest with asterisks.
     * The TLD (e.g. .com) is shown in full.
     * Example: admin@example.com -> ad***@ex*****.com
     *
     * @param email Maskelenecek e-posta adresi.
     * @return The masked e-mail address.
     */
    public static String maskEmail(String email) {
        if (email == null || email.isEmpty() || !email.contains("@")) {
            return "****";
        }

        String[] parts = email.split("@");
        String userName = parts[0];
        String domain = parts[1];

        // 1. Mask the local part (userName)
        String maskedUserName;
        if (userName.length() > 2) {
            maskedUserName = userName.substring(0, 2) + 
                             "*".repeat(userName.length() - 2);
        } else {
            maskedUserName = userName; 
        }

        // 2. Mask the domain while preserving the TLD
        int lastDotIndex = domain.lastIndexOf('.');
        if (lastDotIndex == -1) {
            // TLD yoksa
            String maskedDomainPart = (domain.length() > 2) ? 
                                      domain.substring(0, 2) + "*".repeat(domain.length() - 2) : 
                                      domain;
            return maskedUserName + "@" + maskedDomainPart;
        }

        String domainName = domain.substring(0, lastDotIndex); // example
        String tld = domain.substring(lastDotIndex);          // .com

        // Mask the domain name
        String maskedDomainName;
        if (domainName.length() > 2) {
            maskedDomainName = domainName.substring(0, 2) + 
                               "*".repeat(domainName.length() - 2);
        } else {
            maskedDomainName = domainName;
        }

        return maskedUserName + "@" + maskedDomainName + tld;
    }

    /**
     * Masks a phone number.
     * Common format: show the first 5 digits (country code plus 2-3 digits) and the last 2; mask everything in between.
     * Example: +905321234567 -> +90532*****67
     *
     * @param phoneNumber The phone number to mask.
     * @return The masked phone number.
     */
    public static String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isEmpty() || phoneNumber.length() < 7) {
            return "****";
        }

        // Strip everything except digits and the plus sign
        String cleanedNumber = phoneNumber.replaceAll("[^0-9+]", ""); 

        int length = cleanedNumber.length();
        
        // Number of leading digits to show (country code plus first carrier digits)
        // e.g. +90532 (5 digits), or roughly the first 4-5 digits
        int prefixShowLength = 5; 
        
        // Number of trailing digits to show
        int suffixShowLength = 2; 

        if (length <= prefixShowLength + suffixShowLength) {
             // If the number is too short to mask, return it unchanged.
             return phoneNumber;
        }

        // Maskeleme Bölgesi:
        int maskLength = length - prefixShowLength - suffixShowLength;
        String prefix = cleanedNumber.substring(0, prefixShowLength);
        String suffix = cleanedNumber.substring(length - suffixShowLength);
        
        String maskedNumber = prefix + "*".repeat(maskLength) + suffix;

        return maskedNumber;
    }

}

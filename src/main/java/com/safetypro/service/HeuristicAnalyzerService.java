package com.safetypro.service;

import com.safetypro.model.SafetyResponse.HeuristicResult;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.net.URL;
import java.net.HttpURLConnection;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import org.apache.commons.net.whois.WhoisClient;

@Service
public class HeuristicAnalyzerService {

    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
            ".xyz", ".top", ".club", ".work", ".date", ".faith",
            ".loan", ".download", ".gq", ".ml", ".tk", ".cf"
    );

    private static final List<String> TRUSTED_BRANDS = Arrays.asList(
            "sbi", "hdfc", "icici", "axis", "kotak", "paytm",
            "google", "amazon", "flipkart", "paypal", "facebook",
            "instagram", "whatsapp", "telegram", "microsoft", "apple"
    );

    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
            "secure", "login", "verify", "account", "banking", "password",
            "credit", "wallet", "refund", "lottery", "winner", "gift",
            "free", "bonus", "cashback", "offer"
    );

    // Check if website actually exists
    public boolean doesWebsiteExist(String url) {
        try {
            URL urlObj = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) urlObj.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            int responseCode = connection.getResponseCode();
            return (responseCode >= 200 && responseCode < 400);
        } catch (Exception e) {
            return false;
        }
    }

    // Get website age using WHOIS lookup
    public Map<String, String> getWebsiteAgeInfo(String url) {
        Map<String, String> ageInfo = new HashMap<>();
        ageInfo.put("age", "unknown");
        ageInfo.put("message", "Could not determine website age");
        ageInfo.put("riskScore", "0");
        ageInfo.put("creationDate", "unknown");
        ageInfo.put("monthsOld", "0");

        WhoisClient whois = new WhoisClient();

        try {
            URL urlObj = new URL(url);
            String domain = urlObj.getHost();

            // Remove www. if present
            if (domain.startsWith("www.")) {
                domain = domain.substring(4);
            }

            // Connect to WHOIS server
            whois.connect("whois.verisign-grs.com"); // For .com domains
            String whoisData = whois.query(domain);

            // Parse creation date from WHOIS data
            String creationDateStr = extractCreationDate(whoisData);

            if (creationDateStr != null) {
                ageInfo.put("creationDate", creationDateStr);

                // Parse the date and calculate age
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
                LocalDate creationDate = LocalDate.parse(creationDateStr, formatter);
                LocalDate now = LocalDate.now();

                Period period = Period.between(creationDate, now);
                int years = period.getYears();
                int months = period.getMonths();
                int totalMonths = years * 12 + months;

                ageInfo.put("monthsOld", String.valueOf(totalMonths));

                if (years > 0) {
                    ageInfo.put("age", "old");
                    ageInfo.put("message", String.format("✅ Website created %d year%s %d month%s ago",
                            years, years > 1 ? "s" : "", months, months > 1 ? "s" : ""));
                    ageInfo.put("riskScore", "0");
                    ageInfo.put("color", "GREEN");
                }
                else if (totalMonths >= 12) {
                    ageInfo.put("age", "old");
                    ageInfo.put("message", String.format("✅ Website created %d month%s ago",
                            totalMonths, totalMonths > 1 ? "s" : ""));
                    ageInfo.put("riskScore", "0");
                    ageInfo.put("color", "GREEN");
                }
                else if (totalMonths >= 6) {
                    ageInfo.put("age", "medium");
                    ageInfo.put("message", String.format("⚠️ Website created %d month%s ago (relatively new)",
                            totalMonths, totalMonths > 1 ? "s" : ""));
                    ageInfo.put("riskScore", "10");
                    ageInfo.put("color", "YELLOW");
                }
                else {
                    ageInfo.put("age", "new");
                    ageInfo.put("message", String.format("⚠️⚠️ VERY NEW website - created only %d month%s ago!",
                            totalMonths, totalMonths > 1 ? "s" : ""));
                    ageInfo.put("riskScore", "20");
                    ageInfo.put("color", "YELLOW");
                }
            }

            whois.disconnect();

        } catch (Exception e) {
            // If WHOIS fails, use simulated age as fallback
            ageInfo = simulateAgeFallback(url);
        }

        return ageInfo;
    }

    // Extract creation date from WHOIS data
    private String extractCreationDate(String whoisData) {
        String[] lines = whoisData.split("\n");
        for (String line : lines) {
            line = line.toLowerCase();
            if (line.contains("creation date") || line.contains("created on") ||
                    line.contains("registered on") || line.contains("domain created")) {
                String[] parts = line.split(":");
                if (parts.length > 1) {
                    String date = parts[1].trim();
                    // Extract just the date part (YYYY-MM-DD)
                    if (date.matches(".*\\d{4}-\\d{2}-\\d{2}.*")) {
                        return date.substring(0, 10);
                    }
                }
            }
        }
        return null;
    }

    // Fallback method when WHOIS fails
    private Map<String, String> simulateAgeFallback(String url) {
        Map<String, String> ageInfo = new HashMap<>();

        try {
            URL urlObj = new URL(url);
            String domain = urlObj.getHost();

            // Simulate based on domain patterns
            if (domain.endsWith(".xyz") || domain.endsWith(".top") ||
                    domain.endsWith(".club") || domain.endsWith(".work") ||
                    domain.endsWith(".date") || domain.endsWith(".faith")) {

                ageInfo.put("age", "new");
                ageInfo.put("message", "⚠️ Website uses a new domain extension (often used for temporary sites)");
                ageInfo.put("riskScore", "15");
                ageInfo.put("color", "YELLOW");
                ageInfo.put("creationDate", "estimated: recent");
                ageInfo.put("monthsOld", "3");
            }
            else if (domain.contains("google") || domain.contains("amazon") ||
                    domain.contains("facebook") || domain.contains("microsoft") ||
                    domain.contains("flipkart") || domain.contains("paytm")) {

                ageInfo.put("age", "old");
                ageInfo.put("message", "✅ Established website (many years old)");
                ageInfo.put("riskScore", "0");
                ageInfo.put("color", "GREEN");
                ageInfo.put("creationDate", "estimated: 10+ years");
                ageInfo.put("monthsOld", "120");
            }
            else {
                ageInfo.put("age", "unknown");
                ageInfo.put("message", "ℹ️ Website age could not be verified");
                ageInfo.put("riskScore", "5");
                ageInfo.put("color", "BLUE");
                ageInfo.put("creationDate", "unknown");
                ageInfo.put("monthsOld", "0");
            }

        } catch (Exception e) {
            ageInfo.put("age", "unknown");
            ageInfo.put("message", "Could not determine website age");
            ageInfo.put("riskScore", "0");
            ageInfo.put("color", "BLUE");
        }

        return ageInfo;
    }

    public HeuristicResult analyze(String url) {
        HeuristicResult result = new HeuristicResult();
        List<String> flags = new ArrayList<>();
        int riskScore = 0;

        try {
            // FIRST: Check if website exists
            if (!doesWebsiteExist(url)) {
                flags.add("🚫 This website does NOT exist or cannot be reached");
                riskScore = 100;
                result.setRiskScore(riskScore);
                result.setFlags(flags);
                result.setSummary("WEBSITE NOT FOUND - Domain may be unregistered");
                return result;
            }

            // GET WEBSITE AGE INFORMATION
            Map<String, String> ageInfo = getWebsiteAgeInfo(url);
            int monthsOld = Integer.parseInt(ageInfo.get("monthsOld"));

            // Add age flag with months
            if (monthsOld < 12) {
                flags.add(ageInfo.get("message"));
                riskScore += Integer.parseInt(ageInfo.get("riskScore"));
            }

            // REST OF HEURISTIC ANALYSIS
            URI uri = new URI(url);
            String domain = uri.getHost();
            String lowerUrl = url.toLowerCase();

            if (domain != null) {
                for (String tld : SUSPICIOUS_TLDS) {
                    if (domain.endsWith(tld)) {
                        flags.add("Suspicious domain ending: " + tld);
                        riskScore += 25;
                        break;
                    }
                }

                for (String brand : TRUSTED_BRANDS) {
                    if (domain.contains(brand) && !isLegitimateDomain(domain, brand)) {
                        flags.add("Possible impersonation of " + brand);
                        riskScore += 35;
                        break;
                    }
                }

                int subdomainCount = domain.split("\\.").length - 2;
                if (subdomainCount > 2) {
                    flags.add("Too many subdomains");
                    riskScore += 5;
                }
            }

            if (Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+").matcher(domain != null ? domain : "").find()) {
                flags.add("Uses IP address instead of domain name");
                riskScore += 40;
            }

            if (!url.startsWith("https://")) {
                flags.add("No HTTPS security");
                riskScore += 10;
            }

            for (String keyword : SUSPICIOUS_KEYWORDS) {
                if (lowerUrl.contains(keyword)) {
                    flags.add("Contains '" + keyword + "'");
                    riskScore += 5;
                    break;
                }
            }

            if (url.length() > 100) {
                flags.add("Unusually long URL");
                riskScore += 5;
            }

            if (url.contains("@")) {
                flags.add("Contains @ symbol");
                riskScore += 10;
            }

            riskScore = Math.min(riskScore, 100);

        } catch (Exception e) {
            flags.add("Invalid URL format");
            riskScore = 50;
        }

        result.setRiskScore(riskScore);
        result.setFlags(flags);

        if (flags.isEmpty()) {
            result.setSummary("No suspicious patterns detected");
        } else {
            result.setSummary(String.format("Found %d points to check", flags.size()));
        }

        return result;
    }

    private boolean isLegitimateDomain(String domain, String brand) {
        String lowerDomain = domain.toLowerCase();
        String lowerBrand = brand.toLowerCase();

        return lowerDomain.equals(lowerBrand + ".com") ||
                lowerDomain.equals("www." + lowerBrand + ".com") ||
                lowerDomain.equals(lowerBrand + ".org") ||
                lowerDomain.equals("www." + lowerBrand + ".org") ||
                lowerDomain.equals(lowerBrand + ".in") ||
                lowerDomain.equals("www." + lowerBrand + ".in");
    }
}
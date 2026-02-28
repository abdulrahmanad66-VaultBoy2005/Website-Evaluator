package com.safetypro.model;

import java.time.Instant;
import java.util.List;

public class SafetyResponse {
    private String url;
    private String domain;
    private int riskScore;
    private String riskLevel;
    private String verdict;
    private String advice;
    private String colorCode;
    private String emoji;
    private Instant checkedAt;
    private String requestId;
    private List<String> warnings;

    // Add these two missing fields
    private GoogleResult googleSafeBrowsing;
    private HeuristicResult heuristicAnalysis;

    // Google Result inner class
    public static class GoogleResult {
        private boolean threatDetected;
        private List<String> threats;
        private String summary;

        public GoogleResult() {}

        public static GoogleResult safe() {
            GoogleResult result = new GoogleResult();
            result.threatDetected = false;
            result.summary = "No threats detected by Google";
            return result;
        }

        public static GoogleResult threats(List<String> threats) {
            GoogleResult result = new GoogleResult();
            result.threatDetected = true;
            result.threats = threats;
            result.summary = "Google detected: " + String.join(", ", threats);
            return result;
        }

        // Getters and setters
        public boolean isThreatDetected() { return threatDetected; }
        public void setThreatDetected(boolean threatDetected) { this.threatDetected = threatDetected; }
        public List<String> getThreats() { return threats; }
        public void setThreats(List<String> threats) { this.threats = threats; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
    }

    // Heuristic Result inner class
    public static class HeuristicResult {
        private int riskScore;
        private List<String> flags;
        private String summary;

        public HeuristicResult() {}

        // Getters and setters
        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
        public List<String> getFlags() { return flags; }
        public void setFlags(List<String> flags) { this.flags = flags; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
    }

    // Constructor
    public SafetyResponse(String url) {
        this.url = url;
        this.checkedAt = Instant.now();
        this.requestId = "REQ" + System.currentTimeMillis();
    }

    // Getters and setters for main class
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public String getAdvice() { return advice; }
    public void setAdvice(String advice) { this.advice = advice; }

    public String getColorCode() { return colorCode; }
    public void setColorCode(String colorCode) { this.colorCode = colorCode; }

    public String getEmoji() { return emoji; }
    public void setEmoji(String emoji) { this.emoji = emoji; }

    public Instant getCheckedAt() { return checkedAt; }
    public String getRequestId() { return requestId; }

    public List<String> getWarnings() { return warnings; }
    public void setWarnings(List<String> warnings) { this.warnings = warnings; }

    // === ADD THESE TWO MISSING METHODS ===
    public GoogleResult getGoogleSafeBrowsing() {
        return googleSafeBrowsing;
    }

    public void setGoogleSafeBrowsing(GoogleResult googleSafeBrowsing) {
        this.googleSafeBrowsing = googleSafeBrowsing;
    }

    public HeuristicResult getHeuristicAnalysis() {
        return heuristicAnalysis;
    }

    public void setHeuristicAnalysis(HeuristicResult heuristicAnalysis) {
        this.heuristicAnalysis = heuristicAnalysis;
    }
}
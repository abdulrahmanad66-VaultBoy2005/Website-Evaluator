package com.safetypro.service;

import com.safetypro.model.SafetyResponse;
import com.safetypro.model.SafetyResponse.GoogleResult;
import com.safetypro.model.SafetyResponse.HeuristicResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@Service
public class SafetyOrchestratorService {

    @Autowired
    private GoogleSafeBrowsingService googleService;

    @Autowired
    private HeuristicAnalyzerService heuristicService;

    public SafetyResponse checkUrl(String url) {
        url = normalizeUrl(url);
        SafetyResponse response = new SafetyResponse(url);

        try {
            URI uri = new URI(url);
            response.setDomain(uri.getHost());
        } catch (Exception e) {
            response.setDomain("invalid");
        }

        // STEP 1: Check with Google Safe Browsing FIRST
        GoogleResult googleResult = googleService.checkUrl(url);
        response.setGoogleSafeBrowsing(googleResult);

        // STEP 2: If Google says MALICIOUS - show RED immediately
        if (googleResult.isThreatDetected()) {
            response.setColorCode("RED");
            response.setEmoji("🚫🚫");
            response.setVerdict("DANGEROUS - This website is confirmed malicious!");
            response.setAdvice("This website is known to be dangerous. Close it immediately");

            List<String> warnings = new ArrayList<>();
            warnings.add(googleResult.getSummary());
            response.setWarnings(warnings);

            return response;
        }

        // STEP 3: Google says SAFE - NOW run Heuristic Engine
        HeuristicResult heuristicResult = heuristicService.analyze(url);
        response.setHeuristicAnalysis(heuristicResult);

        // STEP 4: Generate verdict based on heuristic score
        int heuristicScore = heuristicResult.getRiskScore();

        if (heuristicScore >= 70) {
            response.setColorCode("RED");
            response.setEmoji("🚫🚫");
            response.setVerdict("DANGEROUS - Suspicious website detected!");
            response.setAdvice("This website has multiple warning signs. Do not visit!");
        }
        else if (heuristicScore >= 50) {
            response.setColorCode("ORANGE");
            response.setEmoji("🚫");
            response.setVerdict("SUSPICIOUS - Be very careful!");
            response.setAdvice("This website shows strong signs of being a scam.");
        }
        else if (heuristicScore >= 30) {
            response.setColorCode("YELLOW");
            response.setEmoji("⚠️");
            response.setVerdict("CAUTION - Some concerns detected");
            response.setAdvice("This website has some suspicious characteristics.");
        }
        else if (heuristicScore >= 10) {
            response.setColorCode("BLUE");
            response.setEmoji("⚠️");
            response.setVerdict("LOW RISK - Minor concerns");
            response.setAdvice("This website has minor issues but is probably safe.");
        }
        else {
            response.setColorCode("GREEN");
            response.setEmoji("✅");
            response.setVerdict("SAFE - This website appears legitimate");
            response.setAdvice("This website appears legitimate and safe to use.");
        }

        // STEP 5: Add warnings
        if (heuristicResult.getFlags() != null && !heuristicResult.getFlags().isEmpty()) {
            response.setWarnings(heuristicResult.getFlags());
        }

        return response;
    }

    private String normalizeUrl(String url) {
        url = url.trim();
        if (!url.startsWith("http")) {
            url = "https://" + url;
        }
        return url;
    }
}
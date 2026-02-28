package com.safetypro.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetypro.model.SafetyResponse.GoogleResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.*;

@Service
public class GoogleSafeBrowsingService {

    @Value("${google.safe-browsing.api-key}")
    private String apiKey;

    @Value("${google.safe-browsing.url}")
    private String apiUrl;

    @Value("${google.safe-browsing.client-id}")
    private String clientId;

    @Value("${google.safe-browsing.client-version}")
    private String clientVersion;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public GoogleSafeBrowsingService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    public GoogleResult checkUrl(String url) {
        try {
            Map<String, Object> requestBody = new HashMap<>();

            Map<String, Object> client = new HashMap<>();
            client.put("clientId", clientId);
            client.put("clientVersion", clientVersion);
            requestBody.put("client", client);

            Map<String, Object> threatInfo = new HashMap<>();
            threatInfo.put("threatTypes", Arrays.asList(
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"
            ));
            threatInfo.put("platformTypes", Arrays.asList("ANY_PLATFORM"));
            threatInfo.put("threatEntryTypes", Arrays.asList("URL"));

            List<Map<String, String>> threatEntries = new ArrayList<>();
            Map<String, String> entry = new HashMap<>();
            entry.put("url", url);
            threatEntries.add(entry);
            threatInfo.put("threatEntries", threatEntries);

            requestBody.put("threatInfo", threatInfo);

            String fullUrl = apiUrl + "?key=" + apiKey;
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    fullUrl, HttpMethod.POST, entity, String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                JsonNode root = objectMapper.readTree(response.getBody());

                if (root.has("matches")) {
                    List<String> threats = new ArrayList<>();
                    JsonNode matches = root.get("matches");

                    for (JsonNode match : matches) {
                        threats.add(match.get("threatType").asText());
                    }

                    return GoogleResult.threats(threats);
                }
            }

            return GoogleResult.safe();

        } catch (Exception e) {
            System.err.println("Error checking Google Safe Browsing: " + e.getMessage());
            GoogleResult error = GoogleResult.safe();
            error.setSummary("Google check failed: " + e.getMessage());
            return error;
        }
    }
}
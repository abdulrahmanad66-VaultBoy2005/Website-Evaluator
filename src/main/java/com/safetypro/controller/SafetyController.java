package com.safetypro.controller;

import com.safetypro.model.SafetyResponse;
import com.safetypro.service.SafetyOrchestratorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")  // Allows anyone to use our API
public class SafetyController {

    @Autowired
    private SafetyOrchestratorService orchestratorService;

    // POST endpoint - for form submissions
    @PostMapping("/check")
    public ResponseEntity<SafetyResponse> checkUrl(@RequestBody UrlRequest request) {
        SafetyResponse response = orchestratorService.checkUrl(request.getUrl());
        return ResponseEntity.ok(response);
    }

    // GET endpoint - for direct browser access
    @GetMapping("/check")
    public ResponseEntity<SafetyResponse> checkUrlGet(@RequestParam String url) {
        SafetyResponse response = orchestratorService.checkUrl(url);
        return ResponseEntity.ok(response);
    }

    // Health check endpoint - to see if server is running
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "running",
                "service", "Website Evaluator",
                "message", "Server is up and running!"
        ));
    }
    @GetMapping("/")
    public ResponseEntity<String> root() {
        return ResponseEntity.ok("Website Evaluator is running!");
    }

    // Inner class for receiving URL requests
    public static class UrlRequest {
        @NotBlank(message = "URL is required")
        private String url;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
    }
}
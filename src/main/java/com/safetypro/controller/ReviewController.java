package com.safetypro.controller;

import com.safetypro.model.Review;
import com.safetypro.service.ReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.Map;

@RestController
@RequestMapping("/api/reviews")
@CrossOrigin(origins = "*")
public class ReviewController {

    @Autowired
    private ReviewService reviewService;

    @PostMapping("/add")
    public ResponseEntity<?> addReview(@Valid @RequestBody ReviewRequest request) {
        try {
            Review review = reviewService.addReview(
                    request.getUrl(),
                    request.getUserName(),
                    request.getRating(),
                    request.getComment()
            );

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Review added successfully!",
                    "review", review
            ));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/domain/{domain}")
    public ResponseEntity<Map<String, Object>> getDomainReviews(@PathVariable String domain) {
        return ResponseEntity.ok(reviewService.getReviewStats(domain));
    }

    public static class ReviewRequest {
        @NotBlank(message = "URL is required")
        private String url;

        private String userName;

        @Min(1)
        @Max(5)
        private int rating;

        @NotBlank(message = "Comment is required")
        @Size(min = 5, max = 500, message = "Comment must be between 5 and 500 characters")
        private String comment;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }

        public String getUserName() { return userName; }
        public void setUserName(String userName) { this.userName = userName; }

        public int getRating() { return rating; }
        public void setRating(int rating) { this.rating = rating; }

        public String getComment() { return comment; }
        public void setComment(String comment) { this.comment = comment; }
    }
}
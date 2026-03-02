package com.safetypro.service;

import com.safetypro.model.Review;
import com.safetypro.repository.ReviewRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReviewService {

    @Autowired
    private ReviewRepository reviewRepository;

    @Autowired
    private HttpServletRequest request;

    @Transactional
    public Review addReview(String url, String userName, int rating, String comment) {
        try {
            // Step 1: Normalize URL (add https:// if missing)
            if (!url.startsWith("http")) {
                url = "https://" + url;
            }

            // Step 2: Extract domain properly
            URI uri = new URI(url);
            String domain = uri.getHost();

            // Step 3: Remove www. if present
            if (domain != null && domain.startsWith("www.")) {
                domain = domain.substring(4);
            }

            // Step 4: Validate domain is not null
            if (domain == null || domain.isEmpty()) {
                // Fallback: extract from URL string
                String[] parts = url.split("/");
                if (parts.length > 2) {
                    domain = parts[2].replace("www.", "");
                } else {
                    throw new RuntimeException("Could not extract domain from URL");
                }
            }

            // Step 5: Create and populate review
            Review review = new Review();
            review.setDomain(domain);
            review.setUrl(url);
            review.setUserName(userName != null && !userName.trim().isEmpty() ? userName : "Anonymous");
            review.setRating(rating);
            review.setComment(comment);
            review.setIpAddress(getClientIp());

            // Step 6: Save to database
            return reviewRepository.save(review);

        } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid URL format: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error adding review: " + e.getMessage());
        }
    }

    public Map<String, Object> getReviewsForDomain(String domain) {
        Map<String, Object> response = new HashMap<>();

        try {
            List<Review> reviews = reviewRepository.findByDomainOrderByCreatedAtDesc(domain);
            Double avgRating = reviewRepository.getAverageRating(domain);
            Long count = reviewRepository.getReviewCount(domain);

            response.put("reviews", reviews);
            response.put("totalCount", count != null ? count : 0);
            response.put("averageRating", avgRating != null ? Math.round(avgRating * 10) / 10.0 : 0);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("reviews", List.of());
            response.put("totalCount", 0);
            response.put("averageRating", 0);
        }

        return response;
    }

    private String getClientIp() {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    public Map<String, Object> getReviewStats(String domain) {
        return getReviewsForDomain(domain); // Call the existing method
    }
}
package com.safetypro.service;

import com.safetypro.model.Review;
import com.safetypro.repository.ReviewRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReviewService {

    @Autowired
    private ReviewRepository reviewRepository;

    @Autowired
    private HttpServletRequest request;

    public Review addReview(String url, String userName, int rating, String comment) {
        try {
            URI uri = new URI(url);
            String domain = uri.getHost();

            Review review = new Review();
            review.setDomain(domain);
            review.setUrl(url);
            review.setUserName(userName);
            review.setRating(rating);
            review.setComment(comment);
            review.setIpAddress(getClientIp());

            return reviewRepository.save(review);

        } catch (Exception e) {
            throw new RuntimeException("Error adding review: " + e.getMessage());
        }
    }

    public List<Review> getReviewsForDomain(String domain) {
        return reviewRepository.findByDomainOrderByCreatedAtDesc(domain);
    }

    public Map<String, Object> getReviewStats(String domain) {
        Map<String, Object> stats = new HashMap<>();

        List<Review> reviews = reviewRepository.findByDomainOrderByCreatedAtDesc(domain);
        Double avgRating = reviewRepository.getAverageRating(domain);
        Long count = reviewRepository.getReviewCount(domain);

        stats.put("reviews", reviews);
        stats.put("totalCount", count != null ? count : 0);
        stats.put("averageRating", avgRating != null ? Math.round(avgRating * 10) / 10.0 : 0);

        return stats;
    }

    private String getClientIp() {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
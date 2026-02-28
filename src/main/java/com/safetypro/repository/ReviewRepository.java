package com.safetypro.repository;

import com.safetypro.model.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ReviewRepository extends JpaRepository<Review, Long> {

    // Get all reviews for a domain, newest first
    List<Review> findByDomainOrderByCreatedAtDesc(String domain);

    // Get average rating for a domain
    @Query("SELECT AVG(r.rating) FROM Review r WHERE r.domain = :domain")
    Double getAverageRating(@Param("domain") String domain);

    // Get count of reviews for a domain
    @Query("SELECT COUNT(r) FROM Review r WHERE r.domain = :domain")
    Long getReviewCount(@Param("domain") String domain);
}
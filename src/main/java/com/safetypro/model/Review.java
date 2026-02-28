package com.safetypro.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Entity
@Table(name = "reviews")
public class Review {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String domain;

    private String url;

    private String userName;

    @Column(nullable = false)
    private int rating; // 1 to 5 stars

    @Column(length = 1000, nullable = false)
    private String comment;

    private LocalDateTime createdAt;

    private String ipAddress;

    // Constructor
    public Review() {
        this.createdAt = LocalDateTime.now();
    }

    // Helper method to get star rating as emoji
    public String getStarRating() {
        return "⭐".repeat(rating) + "☆".repeat(5 - rating);
    }

    // Helper method for formatted date
    public String getFormattedDate() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd MMM yyyy, hh:mm a");
        return createdAt.format(formatter);
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getUserName() { return userName != null ? userName : "Anonymous"; }
    public void setUserName(String userName) { this.userName = userName; }

    public int getRating() { return rating; }
    public void setRating(int rating) { this.rating = rating; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
}
package com.example.marketing;

public class MarketingService {

    private final Mailer mailer;

    public MarketingService(Mailer mailer) {
        this.mailer = mailer;
    }

    // Sends a promotional newsletter to a user.
    public void sendPromotion(String userEmail) {
        String campaign = "Summer marketing newsletter";
        mailer.sendEmail(userEmail, campaign);
    }
}

package com.example.OAuth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.time.Instant;

@Controller
public class LoginController {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public LoginController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        if (authentication instanceof OAuth2AuthenticationToken) {
            // Check if access token exists and is valid
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId(),
                authentication.getName()
            );

            if (client != null && client.getAccessToken() != null &&
                client.getAccessToken().getExpiresAt().isAfter(Instant.now())) {
                return "redirect:/profile";
            }
        }

        // If not authenticated, show the index page
        return "index";
    }

    @GetMapping("/profile")
    public String profile(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        if (client != null && client.getAccessToken() != null) {
            if (client.getAccessToken().getExpiresAt().isAfter(Instant.now())) {
                String accessToken = client.getAccessToken().getTokenValue();
                model.addAttribute("accessToken", accessToken);
                model.addAttribute("userAttributes", authentication.getPrincipal().getAttributes());
                return "profile";
            }
        }

        // If no valid token is found, re-authenticate with OAuth
        return "redirect:/oauth2/authorization/google";
    }
}

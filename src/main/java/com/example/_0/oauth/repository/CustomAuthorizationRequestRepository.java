package com.example._0.oauth.repository;

import com.example._0.oauth.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example._0.util.CookieUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Optional;

public class CustomAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String CUSTOM_COOKIE_NAME = "_oauth";

    private final HttpCookieOAuth2AuthorizationRequestRepository delegate;

    public CustomAuthorizationRequestRepository() {
        this.delegate = new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getFromCookie(request).orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            deleteCookie(request, response);
            return;
        }
        String serialized = CookieUtils.serialize(authorizationRequest); // 아래에서 설명
        CookieUtils.addCookie(response, CUSTOM_COOKIE_NAME, serialized, 180);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest authRequest = loadAuthorizationRequest(request);
        deleteCookie(request, response);
        return authRequest;
    }

    private Optional<OAuth2AuthorizationRequest> getFromCookie(HttpServletRequest request) {
        return CookieUtils.getCookie(request, CUSTOM_COOKIE_NAME)
                .map(Cookie::getValue)
                .map(CookieUtils::deserialize);
    }

    private void deleteCookie(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, CUSTOM_COOKIE_NAME);
    }
}

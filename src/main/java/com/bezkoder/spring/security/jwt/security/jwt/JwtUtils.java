package com.bezkoder.spring.security.jwt.security.jwt;

import java.security.Key;
import java.util.Date;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.bezkoder.spring.security.jwt.models.User;
import com.bezkoder.spring.security.jwt.security.services.UserDetailsImpl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${bezkoder.app.jwtSecret}")
  private String jwtSecret;

  @Value("${bezkoder.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  @Value("${bezkoder.app.jwtCookieName}")
  private String jwtCookie;
  
  @Value("${bezkoder.app.jwtRefreshCookieName}")
  private String jwtRefreshCookie;

  public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
    String jwt = generateTokenFromUsername(userPrincipal.getUsername());   
    return generateCookie(jwtCookie, jwt, "/api");
  }
  
  public ResponseCookie generateJwtCookie(User user) {
    String jwt = generateTokenFromUsername(user.getUsername());   
    return generateCookie(jwtCookie, jwt, "/api");
  }
  
  public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
    return generateCookie(jwtRefreshCookie, refreshToken, "/api/auth/refreshtoken");
  }
  
  public String getJwtFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtCookie);
  }
  
  public String getJwtRefreshFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtRefreshCookie);
  }

  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
    return cookie;
  }
  
  public ResponseCookie getCleanJwtRefreshCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookie, null).path("/api/auth/refreshtoken").build();
    return cookie;
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
        .parseClaimsJws(token).getBody().getSubject();
  }

  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }
  
  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
  
  public String generateTokenFromUsername(String username) {   
    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }
    
  private ResponseCookie generateCookie(String name, String value, String path) {
    ResponseCookie cookie = ResponseCookie.from(name, value).path(path).maxAge(24 * 60 * 60).httpOnly(true).build();
    return cookie;
  }
  
  private String getCookieValueByName(HttpServletRequest request, String name) {
    Cookie cookie = WebUtils.getCookie(request, name);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }
  }
}

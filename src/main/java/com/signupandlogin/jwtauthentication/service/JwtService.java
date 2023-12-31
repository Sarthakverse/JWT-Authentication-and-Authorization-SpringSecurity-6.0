package com.signupandlogin.jwtauthentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    //this is the secret key which is used to sign the jwt token
//    private static final String SECRET_KEY = "d7dcb56a5ab7183f206d5e072525d383c7cd0649f3efc8ff6822b432ebb9f4cf";
    private static final String SECRET_KEY = "c8d7c086fe64a415ee1fafe90b1a663ef635f903b129d2bd752af401c817bee0";


    //this method is used to extract the claims from the jwt token
    public <T> T extractClaims(String jwt , Function<Claims , T> claimsResolver) {
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }

    //this method is used to extract the username from the jwt token
    public String extractUsername(String jwt) {
        return extractClaims(jwt , Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>() , userDetails);
    }
    public String generateToken(Map<String,Object> extraClaims
                                , UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24*30))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public Boolean isTokenValid(String jwt , UserDetails userDetails){
        final String username = extractUsername(jwt);
        return (username.equals(userDetails.getUsername())) && !isJwtExpired(jwt);
    }

    private boolean isJwtExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaims(jwt , Claims::getExpiration);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    // this method is used to get the secret key
    private Key getSignInKey() {
        byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

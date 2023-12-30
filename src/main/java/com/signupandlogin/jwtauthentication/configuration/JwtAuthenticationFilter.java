package com.signupandlogin.jwtauthentication.configuration;

import com.signupandlogin.jwtauthentication.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component //component annotation is used to register this class as a bean
@RequiredArgsConstructor // this annotation is used to create a constructor with all the required fields

//Once per request filter is used to intercept every request and check if the request has a valid jwt token
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException
    {
        //get the jwt token from the request header
        final String authorizationHeader = request.getHeader("Authorization");
        final String userEmail;
        //check if the jwt token is null or not
        if(authorizationHeader == null || !(authorizationHeader.startsWith("Bearer")))
        {
            //if the jwt token is null or not valid then we will pass the request to the next filter
            filterChain.doFilter(request,response);
            return;
        }

        //if the jwt token is valid then we will extract the jwt token from the request header
        String jwt = authorizationHeader.substring(7);

        userEmail = jwtService.extractUsername(jwt);
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
            if (jwtService.isTokenValid(jwt, userDetails)) {
                usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            }
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
        filterChain.doFilter(request,response);


    }
}

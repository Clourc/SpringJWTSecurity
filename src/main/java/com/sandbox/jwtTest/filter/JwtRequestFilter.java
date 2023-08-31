package com.sandbox.jwtTest.filter;

import com.sandbox.jwtTest.jwt.Jwt;
import com.sandbox.jwtTest.jwt.UserPrincipal;
import com.sandbox.jwtTest.service.UserDetailsServiceApp;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final Jwt jwtUtil;

    private final UserDetailsServiceApp userDetailsService;

    public JwtRequestFilter(Jwt jwtUtil, UserDetailsServiceApp userDetailsService){
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        System.out.println("authorizationHeader " + authorizationHeader);

        String email = null;
        String token = null;

        //Recupération du token et email depuis header
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            token = authorizationHeader.substring(7);
            email = jwtUtil.extractEmail(token);
        }

        //Vérification du token
        if(email != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserPrincipal userPrincipal = this.userDetailsService.loadUserByEmail(email);
            System.out.println("jwtUtil validateToken " + jwtUtil.validateToken(token, userPrincipal));
            System.out.println("userPrincipal authorities +" + userPrincipal.getAuthorities());

            if(jwtUtil.validateToken(token, userPrincipal)){ //@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                var usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userPrincipal,
                        null,
                        userPrincipal.getAuthorities()
                );
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                System.out.println("usernamePasswordAuthenticationToken " + usernamePasswordAuthenticationToken);
                SecurityContextHolder
                        .getContext()
                        .setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}

package com.example.mssecurity.config;

import com.example.mssecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Si la petición es para /api/auth, no hagas nada y déjala pasar.
        // Esta fue la corrección que hicimos.
        if (request.getServletPath().contains("/api/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 1. Busca el header "Authorization" en la petición
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // Si no hay token, sigue adelante
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extrae el token (quitando "Bearer ")
        jwt = authHeader.substring(7);
        // 3. Extrae el username del token usando JwtService
        username = jwtService.extractUsername(jwt);

        // 4. Si hay username y el usuario no está ya autenticado en el contexto de seguridad...
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            // 5. Valida el token
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // 6. Si es válido, crea un objeto de autenticación y lo guarda en el
                //    SecurityContextHolder. Esto es lo que le dice a Spring Security:
                //    "Este usuario está autenticado para esta petición".
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // Pasa al siguiente filtro en la cadena
        filterChain.doFilter(request, response);
    }
}

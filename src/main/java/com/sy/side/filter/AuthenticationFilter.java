package com.sy.side.filter;

import com.sy.side.jwt.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtProperties jwtProperties;

    // 인증 없이 통과시킬 경로들
    private static final List<String> openPaths = List.of(
            "/v1/cms/auth/signup",
            "/v1/cms"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 1. openPaths에 포함되면 바로 통과
        if (isOpenPath(path)) {
            return chain.filter(exchange);
        }

        // 2. 그 외 요청은 JWT 검사
        String token = extractToken(exchange.getRequest().getHeaders());

        if (token == null || !validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private boolean isOpenPath(String path) {
        System.out.println("[DEBUG] 요청된 path: " + path);
        return openPaths.stream().anyMatch(path::startsWith);
    }

    private String extractToken(HttpHeaders headers) {
        String bearer = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // 검증 성공
            return true;
        } catch (Exception e) {
            // 검증 실패
            return false;
        }
    }

    @Override
    public int getOrder() {
        return -1; // 필터 순서 조정 (낮을수록 먼저 실행)
    }
}

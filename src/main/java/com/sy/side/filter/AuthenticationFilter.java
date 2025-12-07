package com.sy.side.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sy.side.common.entity.MemberSession;
import com.sy.side.common.entity.UserSession;
import com.sy.side.common.entity.UserSession.UserType;
import com.sy.side.jwt.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;

    // 인증 없이 통과시킬 경로들
    private static final List<String> openPaths = List.of(
            "/v1/cms/auth/signup",
            "/v1/cms/auth/login",
            "/v1/cms"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        log.debug("[GATEWAY] 요청 path = {}", path);

        // openPaths에 포함되면 바로 통과 (토큰 없어도 됨)
        if (isOpenPath(path)) {
            return chain.filter(exchange);
        }

        // 그 외 요청은 JWT 검사
        String token = extractToken(exchange.getRequest().getHeaders());

        if (token == null) {
            log.warn("[GATEWAY] 토큰 없음 -> 401");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims;
        try {
            claims = parseClaims(token);
        } catch (Exception e) {
            log.warn("[GATEWAY] 토큰 검증 실패 -> 401", e);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Claims -> UserSession 으로 변환
        UserSession userSession = toUserSession(claims);

        String sessionJson;
        try {
            sessionJson = objectMapper.writeValueAsString(userSession);
        } catch (JsonProcessingException e) {
            log.error("[GATEWAY] UserSession 직렬화 실패", e);
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }

        // 4. 기존 요청에 user-session 헤더를 추가해서 하위 서비스로 전달
        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header("user-session", sessionJson)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return chain.filter(mutatedExchange);
    }

    private boolean isOpenPath(String path) {
        return openPaths.stream().anyMatch(path::startsWith);
    }

    private String extractToken(HttpHeaders headers) {
        String bearer = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    private Claims parseClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * JWT 클레임을 UserSession 객체로 변환
     * 여기서 클레임 키는 "토큰 발급 시에" 넣어준 이름과 맞춰야 함
     */
    private UserSession toUserSession(Claims claims) {

        Long memberId = claims.get("memberId", Long.class);
        String loginType = claims.get("loginType", String.class);
        String snsType = claims.get("snsType", String.class);

        // MemberSession 생성
        MemberSession memberSession = MemberSession.builder()
                .memberId(memberId != null ? memberId : 0L)
                .loginType(loginType)
                .snsType(snsType)
                .build();

        // UserSession 생성
        return UserSession.builder()
                .userType(UserSession.UserType.MEMBER)
                .memberSession(memberSession)
                .build();
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

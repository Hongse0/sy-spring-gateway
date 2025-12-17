package com.sy.side.filter;

import com.sy.side.jwt.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtProperties jwtProperties;

    // 인증 없이 통과시킬 경로들
    private static final List<String> openPaths = List.of(
            "/v1/cms/auth/signup",
            "/v1/cms/auth/login",
            "/v1/cms"
    );

    // downstream으로 전달할 헤더 키 (통일해두면 서비스에서 파싱하기 편함)
    private static final String H_USER_TYPE  = "X-USER-TYPE";   // 예: MEMBER
    private static final String H_MEMBER_ID  = "X-MEMBER-ID";   // 예: 123
    private static final String H_LOGIN_TYPE = "X-LOGIN-TYPE";  // 예: LOCAL, KAKAO ...
    private static final String H_SNS_TYPE   = "X-SNS-TYPE";    // 예: KAKAO, NAVER ...

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        log.debug("[GATEWAY] 요청 path = {}", path);

        // openPaths는 토큰 없이 통과
        if (isOpenPath(path)) {
            return chain.filter(exchange);
        }

        // JWT 추출
        String token = extractToken(exchange.getRequest().getHeaders());
        if (token == null) {
            log.warn("[GATEWAY] 토큰 없음 -> 401, path={}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // JWT 검증 및 Claims 파싱
        Claims claims;
        try {
            claims = parseClaims(token);
        } catch (Exception e) {
            log.warn("[GATEWAY] 토큰 검증 실패 -> 401, path={}", path, e);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Claims에서 필요한 값 추출 (토큰 발급 시 넣은 claim key와 동일해야 함)
        // 타입 이슈 방지: Number로 받고 longValue()로 변환
        String sub = claims.getSubject(); // == claims.get("sub", String.class) 과 동일
        Long memberId = null;
        try {
            memberId = Long.parseLong(sub);
        } catch (Exception e) {
            // sub가 숫자가 아니면 인증 실패 처리
        }

        String loginType = claims.get("loginType", String.class);
        String snsType = claims.get("snsType", String.class);

        // 필수값 체크(원하면 더 엄격하게)
        if (memberId == null) {
            log.warn("[GATEWAY] 토큰 claim(memberId) 누락 -> 401, path={}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 하위 서비스로 사용자 정보 헤더 전달
        Long finalMemberId = memberId;
        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .headers(httpHeaders -> {
                    httpHeaders.remove(H_USER_TYPE);
                    httpHeaders.remove(H_MEMBER_ID);
                    httpHeaders.remove(H_LOGIN_TYPE);
                    httpHeaders.remove(H_SNS_TYPE);

                    httpHeaders.add(H_USER_TYPE, "MEMBER");
                    httpHeaders.add(H_MEMBER_ID, String.valueOf(finalMemberId));
                    if (loginType != null) httpHeaders.add(H_LOGIN_TYPE, loginType);
                    if (snsType != null) httpHeaders.add(H_SNS_TYPE, snsType);
                })
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

    @Override
    public int getOrder() {
        return -1; // 낮을수록 먼저 실행
    }
}

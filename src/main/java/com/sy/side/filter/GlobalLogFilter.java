package com.sy.side.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(0)
public class GlobalLogFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 요청 정보 출력
        log.info("[GlobalFilter] Request: {} {}", exchange.getRequest().getMethod(), exchange.getRequest().getURI());
        log.info("[GlobalFilter] Headers: {}", exchange.getRequest().getHeaders());

        // 다음 필터로 넘기기
        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    log.info("[GlobalFilter] Response status: {}", exchange.getResponse().getStatusCode());
                }));
    }

}

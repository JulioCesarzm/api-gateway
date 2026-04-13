package pe.edu.idat.app_gateway;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter implements WebFilter {

    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/v1/auth/login",
            "/api/v1/auth/validate",
            "/actuator"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String token = extractToken((ServerHttpRequest) exchange.getRequest());
        if (token == null || !isValidToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(enrichHeaders(exchange, token));
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private String extractToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    private boolean isValidToken(String token) {
        // Por ahora: true (sin validación)
        // Futuro: validar con ms-auth
        return true;
    }

    private ServerWebExchange enrichHeaders(ServerWebExchange exchange, String token) {
        return exchange.mutate()
                .request(r -> r.header("X-Authenticated", "true"))
                .build();
    }
}

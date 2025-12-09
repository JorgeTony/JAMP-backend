package com.hospital.inventario.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                // 👇 para probar, permite solo tus frontends conocidos
                .allowedOrigins(
                        "https://jamp-production.up.railway.app",
                        "http://localhost:5173"
                )
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                // no usamos cookies, solo JWT en header, así que lo dejamos en false
                .allowCredentials(false);
    }
}

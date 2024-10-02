package com.springjwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // Allow CORS for all endpoints
                .allowedOrigins("http://localhost:4202") // Your frontend URL
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Allowed methods
                .allowCredentials(true) // Allow credentials
                .allowedHeaders("*"); // Allow all headers
    }
}

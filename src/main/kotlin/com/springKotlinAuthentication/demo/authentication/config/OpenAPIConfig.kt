package com.springKotlinAuthentication.demo.authentication.config

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType
import io.swagger.v3.oas.annotations.info.Contact
import io.swagger.v3.oas.annotations.info.Info
import io.swagger.v3.oas.annotations.info.License
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.security.SecurityScheme
import io.swagger.v3.oas.annotations.servers.Server
import org.springframework.context.annotation.Configuration

@Configuration
@OpenAPIDefinition(
    info = Info(
        contact = Contact(
            name = "Spring Kotlin Authentication Demo",
            email = "kendygitonga@gmail.com",
            url = "https://github.com/Kenato254/spring-kotlin-authentication-demo"
        ),
        description = "A demo project showcasing secure, token-based authentication with Spring Boot, Kotlin, and JWT, running on a free-tier EC2 instance.",
        title = "Spring Boot Kotlin Authentication API",
        version = "1.0.0",
        license = License(name = "MIT License", url = "https://opensource.org/licenses/MIT"),
        termsOfService = "https://github.com/Kenato254/spring-kotlin-authentication-demo/blob/main/TERMS.md"
    ),
    servers = [
        Server(description = "EC2 Development Server", url = "http://54.224.246.132/api"),
        Server(description = "Local Development Server", url = "http://localhost:8080/api")
    ]
)
@SecurityScheme(
    name = "Bearer Authentication",
    type = SecuritySchemeType.HTTP,
    bearerFormat = "JWT",
    scheme = "bearer"
)
class OpenApiConfig

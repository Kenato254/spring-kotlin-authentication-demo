package com.springKotlinAuthentication.demo.authentication.config

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Contact
import io.swagger.v3.oas.annotations.info.Info
import io.swagger.v3.oas.annotations.info.License
import io.swagger.v3.oas.annotations.servers.Server

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
//        termsOfService = "https://github.com/Kenato254/spring-kotlin-authentication-demo/blob/main/TERMS.md"
    ),
    servers = [Server(description = "Development Server", url = "http://localhost:8080/api")]
)
class OpenApiConfig
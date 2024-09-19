package com.springKotlinAuthentication.demo.authentication.jwt.config

import org.springframework.context.annotation.Configuration
import org.springframework.beans.factory.annotation.Value

@Configuration
class JwtProperties {
    @Value("\${spring.security.jwt.secret-key}")
    lateinit var jwtSecret: String

    @Value("\${spring.security.jwt.expiration}")
    var jwtExpiration: Long = 0

    @Value("\${spring.security.jwt.refresh-token.expiration}")
    var refreshTokenExpiration: Long = 0
}

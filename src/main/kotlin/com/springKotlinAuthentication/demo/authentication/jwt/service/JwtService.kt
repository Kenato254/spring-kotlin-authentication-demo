package com.springKotlinAuthentication.demo.authentication.jwt.service

import com.springKotlinAuthentication.demo.authentication.authorization.Role
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.jwt.entity.Token
import io.jsonwebtoken.Claims
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.*
import java.util.function.Function

interface JwtService {
    fun generateToken(
        extraClaims: Map<String, Role?>,
        user: User
    ): String?

    val expiresIn: Long?
    val tokenType: String?

    fun generateRefreshToken(
        extraClaims: Map<String, Role?>,
        user: User
    ): String?

    fun isTokenValid(token: String): Boolean

    fun isTokenExpired(token: String): Boolean

    fun isTokenUserValid(
        userDetails: UserDetails,
        token: String
    ): Boolean

    fun <T> extractClaim(
        token: String,
        claimResolver: Function<Claims, T>
    ): T?

    fun getClaimsFromToken(token: String): Claims?

    fun extractUsername(token: String): String?

    fun extractExpiration(token: String): Date?

    fun extractJwtFromHeader(request: HttpServletRequest): String?

    fun refreshToken(request: HttpServletRequest): String?

    fun extractUserDetailFromRequest(
        request: HttpServletRequest
    ): Pair<UserDetails, String>

    fun saveRefreshToken(user: UserDetails, token: String)

    fun getTokenByUser(user: User): Token?

    fun getAllTokensByUser(userId: UUID): List<Token>

    fun revokeAllTokenByUser(user: User)
}



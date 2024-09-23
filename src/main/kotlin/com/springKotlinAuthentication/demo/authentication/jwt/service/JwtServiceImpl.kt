package com.springKotlinAuthentication.demo.authentication.jwt.service

import com.springKotlinAuthentication.demo.authentication.authorization.Role
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.ExpiredJwtException
import com.springKotlinAuthentication.demo.authentication.jwt.config.JwtProperties
import com.springKotlinAuthentication.demo.authentication.jwt.entity.Token
import com.springKotlinAuthentication.demo.authentication.jwt.repository.TokenRepository
import com.springKotlinAuthentication.demo.authentication.service.CustomUserDetailService
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpHeaders
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*
import java.util.function.Function
import javax.crypto.SecretKey

@Service
class JwtServiceImpl(
    private val jwtProperties: JwtProperties,
    private val tokenRepository: TokenRepository,
    private val customUserDetailService: CustomUserDetailService
) : JwtService {
    override val expiresIn: Long?
        get() = jwtProperties.jwtExpiration

    override val tokenType: String?
        get() = "Bearer"

    private val signingKey: SecretKey
        get() = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.jwtSecret))

    override fun generateToken(
        extraClaims: Map<String,Role?>,
        user: User
    ): String? {
        return buildToken(extraClaims, user, jwtProperties.jwtExpiration)
    }

    override fun generateRefreshToken(
        extraClaims: Map<String,Role?>,
        user: User
    ): String {
        return buildToken(extraClaims, user, jwtProperties.refreshTokenExpiration)
    }

    private fun buildToken(
        extraClaims: Map<String,Role?>?,
        user: User,
        expiration: Long
    ): String {
        return Jwts.builder()
            .header().add(mapOf("typ" to "Bearer")).and()
            .subject(user.id.toString())
            .claim("name", user.getFullName())
            .claim("email", user.username)
            .claims(extraClaims)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + expiration))
            .signWith(signingKey)
            .compact()
    }

    override fun isTokenValid(token: String): Boolean {
        return try {
            getClaimsFromToken(token)
                ?: throw MalformedJwtException(Constant.JWT_MALFORMED)
            true
        } catch (e: Exception) {
            false
        }
    }

    override fun isTokenExpired(token: String): Boolean {
        return extractExpiration(token)?.before(Date()) == true
    }

    override fun isTokenUserValid(
        userDetails: UserDetails,
        token: String
    ): Boolean {
        val username = extractUsername(token)
            ?: throw MalformedJwtException(Constant.JWT_MALFORMED)
        return username == userDetails.username
    }

    override fun <T> extractClaim(
        token: String,
        claimResolver: Function<Claims, T>
    ): T {
        val claims = getClaimsFromToken(token)
            ?: throw MalformedJwtException(Constant.JWT_MALFORMED)
        return claimResolver.apply(claims)
    }

    override fun getClaimsFromToken(token: String): Claims? {
        return try {
            Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (e: Exception) {
            null
        }
    }

    override fun extractUsername(token: String): String? {
        return extractClaim(token) { it.subject }
    }

    override fun extractExpiration(token: String): Date? {
        return extractClaim(token) { it.expiration }
    }

    override fun extractJwtFromHeader(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION)
        return if (
            bearerToken != null
            && bearerToken.startsWith("Bearer ")
        ) {
            bearerToken.substring(7)
        } else {
            null
        }
    }

    override fun refreshToken(request: HttpServletRequest): String? {
        val userDetails = extractUserDetailFromRequest(request).first
        val token = extractUserDetailFromRequest(request).second
        val roles = (userDetails as User).role

        return if (isTokenUserValid(userDetails, token)) {
            generateToken(mapOf("roles" to roles), userDetails)
        } else {
            null
        }
    }

    @Transactional(readOnly = true)
    override fun extractUserDetailFromRequest(
        request: HttpServletRequest
    ): Pair<UserDetails, String> {
        val token = extractJwtFromHeader(request)
            ?: throw MalformedJwtException(Constant.JWT_MALFORMED)

        if (isTokenExpired(token)) {
            throw ExpiredJwtException(Constant.JWT_EXPIRED)
        }

        if (!isTokenValid(token)) {
            throw MalformedJwtException(Constant.JWT_MALFORMED)
        }

        val username = extractUsername(token)
            ?: throw MalformedJwtException(Constant.JWT_MALFORMED)

        val userDetails = customUserDetailService.loadUserByUsername(username)
        return Pair(userDetails, token)
    }

    @Transactional
    override fun saveRefreshToken(user: UserDetails, token: String) {
        val userEntity = customUserDetailService.loadUserByEmail(user.username)
        val tokenHash = Token.encryptToken(token)
        tokenRepository.save(
            Token(token = tokenHash, user = userEntity)
        )
    }

    @Transactional
    override fun revokeAllTokenByUser(user: User) {
        val tokens = tokenRepository.findAllValidTokensByUser(user.id!!)

        tokens.forEach { token ->
            token.run { isRevoked = true }
        }
        tokenRepository.saveAll(tokens)
    }

    @Transactional(readOnly = true)
    override fun getTokenByUser(user: User): Token? {
        return tokenRepository.findFirstByUserAndIsExpiredFalse(user)
    }

    @Transactional(readOnly = true)
    override fun getAllTokensByUser(userId: UUID): List<Token> {
        return tokenRepository.findAllValidTokensByUser(userId)
    }
}
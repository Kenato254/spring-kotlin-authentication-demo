package com.springKotlinAuthentication.demo.authentication.jwt.entity

import com.springKotlinAuthentication.demo.authentication.entity.User
import jakarta.persistence.*
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.time.Instant


@Entity(name = "refresh_tokens")
data class Token(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    var id: Long = 0,

    @Column(nullable = false)
    var token: String,

    @Column(name = "is_revoked", nullable = false)
    var isRevoked: Boolean = false,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    val user: User,

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = Instant.now(),
) {
    companion object {
        fun encryptToken(token: String): String {
            return BCryptPasswordEncoder().encode(token)
        }
    }

    fun checkToken(rawToken: String): Boolean {
        return BCryptPasswordEncoder().matches(rawToken, this.token)
    }

    override fun toString(): String {
        return "Token(id=$id, isRevoked=$isRevoked, user=${user.id}, createdAt=$createdAt, token=$token)"
    }
}

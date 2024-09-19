package com.springKotlinAuthentication.demo.authentication.entity

import jakarta.persistence.*
import java.time.Instant

@Entity(name = "confirmation_tokens")
data class ConfirmationToken(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long = 0,

    @Column(nullable = false)
    val token: String,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(nullable = false, name = "user_id")
    val user: User,

    @Column(nullable = false)
    val expiresAt: Instant,

    var confirmedAt: Instant? = null,

    @Column(nullable = false, updatable = false)
    val createdAt: Instant = Instant.now()

) {
    @PreUpdate
    fun onUpdate() {
        confirmedAt = Instant.now()
    }

    override fun toString(): String {
        val maskedToken = token.replaceRange(
            0,
            token.length - 4,
            "*".repeat(token.length - 4)
        )
        return "ConfirmationToken(id=$id, token=$maskedToken, userId=${user.id}, " +
                "expiresAt=$expiresAt, confirmedAt=$confirmedAt, createdAt=$createdAt)"
    }
}

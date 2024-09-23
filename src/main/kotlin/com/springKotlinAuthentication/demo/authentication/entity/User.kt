package com.springKotlinAuthentication.demo.authentication.entity

import com.springKotlinAuthentication.demo.authentication.authorization.Role
import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.time.Instant
import java.time.LocalDate
import java.util.*


@Entity(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,

    @Column(name = "email", nullable = false, unique = true)
    var email: String,

    @Column(name = "password", nullable = false)
    private var password: String,

    @Column(name = "first_name", nullable = false)
    var firstName: String,

    @Column(name = "last_name", nullable = false)
    var lastName: String,

    @Column(name = "date_of_birth", nullable = false)
    val dateOfBirth: LocalDate,

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    var role: Role = Role.USER,

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),

    @Column(name = "is_expired", nullable = false)
    var expired: Boolean = false,

    @Column(name = "is_locked", nullable = false)
    var locked: Boolean = false,

    @Column(name = "is_credential_expired", nullable = false)
    var credentialExpired: Boolean = false,

    @Column(name = "is_enabled", nullable = false)
    var enabled: Boolean = false
) : UserDetails {

    @PreUpdate
    fun onUpdate() {
        updatedAt = Instant.now()
    }

    companion object {
        private val passwordEncoder = BCryptPasswordEncoder()
        fun encryptPassword(password: String): String {
            return passwordEncoder.encode(password)
        }
    }

    fun setPassword(password: String) {
        this.password = encryptPassword(password)
    }

    fun checkPassword(password: String): Boolean {
        return Companion.passwordEncoder.matches(password, this.password)
    }

    fun getFullName(): String = "$firstName $lastName"

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return mutableListOf(SimpleGrantedAuthority(role.name))
    }

    override fun getPassword(): String {
        return password
    }

    override fun getUsername(): String {
        return email
    }

    override fun isAccountNonExpired(): Boolean {
        return !expired
    }

    override fun isAccountNonLocked(): Boolean {
        return !locked
    }

    override fun isCredentialsNonExpired(): Boolean {
        return !credentialExpired
    }

    override fun isEnabled(): Boolean {
        return enabled
    }
}


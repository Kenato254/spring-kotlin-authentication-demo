package com.springKotlinAuthentication.demo.authentication.repository

import com.springKotlinAuthentication.demo.authentication.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.time.LocalDate
import java.util.*

@Repository
interface UserRepository : JpaRepository<User, UUID> {
    fun findByEmail(email: String): User?

    @Query(
        "SELECT u FROM users u WHERE u.date_of_birth = :dob ORDER BY u.date_of_birth DESC",
        nativeQuery = true
    )
    fun findByDob(dob: LocalDate): List<User>

    @Query("SELECT COUNT(u) > 0 FROM users u WHERE u.email = :email")
    fun emailExists(email: String): Boolean
}
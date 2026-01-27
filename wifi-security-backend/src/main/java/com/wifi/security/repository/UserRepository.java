package com.wifi.security.repository;

import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for User entity operations.
 */
@Repository
public interface UserRepository extends JpaRepository<User, String> {

    /**
     * Find a user by email address.
     */
    Optional<User> findByEmail(String email);

    /**
     * Find a user by email address with institute eagerly fetched.
     */
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.institute WHERE u.email = :email")
    Optional<User> findByEmailWithInstitute(@Param("email") String email);

    /**
     * Check if an email already exists.
     */
    boolean existsByEmail(String email);

    /**
     * Find all users by institute and role.
     */
    List<User> findByInstituteAndRole(Institute institute, UserRole role);

    /**
     * Find all users in an institute.
     */
    List<User> findByInstitute(Institute institute);
}

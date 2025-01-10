package com.krishna.authenticationservice.repository;

import com.krishna.authenticationservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
        User findByUsername(String username);
}

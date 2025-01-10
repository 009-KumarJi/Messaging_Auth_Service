package com.krishna.authenticationservice.service;

import com.krishna.authenticationservice.model.User;
import com.krishna.authenticationservice.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepo repo;
    private BCryptPasswordEncoder encoder=new BCryptPasswordEncoder(12);

    public User saveUser(User user) {
    try {
        user.setPasswordHash(encoder.encode(user.getPasswordHash()));
        return repo.save(user);
    } catch (DataIntegrityViolationException e) {
        throw new RuntimeException("Username already exists");
    }
}


    public User findByUsername(String username) {
        return repo.findByUsername(username);
    }
}

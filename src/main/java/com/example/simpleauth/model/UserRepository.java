// filepath: c:\Users\Badhrinarayanan\Desktop\FS2\my-simple-website\src\main\java\com\example\simpleauth\repository\UserRepository.java
package com.example.simpleauth.repository;

import com.example.simpleauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByEmail(String email);
  Optional<User> findByToken(String token);
}
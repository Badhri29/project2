// filepath: c:\Users\Badhrinarayanan\Desktop\FS2\my-simple-website\src\main\java\com\example\simpleauth\controller\AuthController.java
package com.example.simpleauth.controller;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.security.crypto.bcrypt.BCrypt;
import java.util.*;
import com.example.simpleauth.model.User;
import com.example.simpleauth.repository.UserRepository;

@RestController
@RequestMapping("/")
@CrossOrigin(origins = "*")
public class AuthController {
  @Autowired
  private UserRepository userRepository;

  record RegisterRequest(@NotBlank String name, @Email String email, @NotBlank String password) {}
  record LoginRequest(@Email String email, @NotBlank String password) {}

  @PostMapping("/register")
  public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    if (userRepository.findByEmail(req.email()).isPresent()) {
      return ResponseEntity.badRequest().body(Map.of("error", "Email already in use"));
    }
    User u = new User();
    u.setName(req.name());
    u.setEmail(req.email());
    u.setPasswordHash(BCrypt.hashpw(req.password(), BCrypt.gensalt()));
    u.setToken(null);
    userRepository.save(u);
    return ResponseEntity.ok(Map.of("status", "registered"));
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
    var userOpt = userRepository.findByEmail(req.email());
    if (userOpt.isEmpty()) return ResponseEntity.status(401).body(Map.of("error","invalid credentials"));
    User u = userOpt.get();
    if (!BCrypt.checkpw(req.password(), u.getPasswordHash())) {
      return ResponseEntity.status(401).body(Map.of("error","invalid credentials"));
    }
    String token = UUID.randomUUID().toString();
    u.setToken(token);
    userRepository.save(u);
    return ResponseEntity.ok(Map.of("token", token, "name", u.getName()));
  }

  @GetMapping("/profile")
  public ResponseEntity<?> profile(@RequestHeader(name="X-Auth-Token", required=false) String token) {
    if (token == null) return ResponseEntity.status(401).body(Map.of("error","missing token"));
    var uOpt = userRepository.findByToken(token);
    if (uOpt.isEmpty()) return ResponseEntity.status(401).body(Map.of("error","invalid token"));
    User u = uOpt.get();
    return ResponseEntity.ok(Map.of("message", "Welcome " + u.getName() + ", you are logged in.", "email", u.getEmail()));
  }

  @PostMapping(path = "register", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ResponseEntity<String> registerForm(@RequestParam String name,
                                             @RequestParam String email,
                                             @RequestParam String password) {
    if (userRepository.findByEmail(email).isPresent()) {
      String body = "<html><body><main class='center'><div class='card'><h2>Email already in use</h2>"
                  + "<p><a href='/register.html'>Back to register</a></p></div></main></body></html>";
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.TEXT_HTML).body(body);
    }
    User u = new User();
    u.setName(name);
    u.setEmail(email);
    u.setPasswordHash(BCrypt.hashpw(password, BCrypt.gensalt()));
    u.setToken(null);
    userRepository.save(u);
    String body = "<html><body><main class='center'><div class='card'><h2>Registered</h2>"
                + "<p>Now <a href='/login.html'>login</a>.</p></div></main></body></html>";
    return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(body);
  }

  @PostMapping(path = "login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ResponseEntity<String> loginForm(@RequestParam String email,
                                          @RequestParam String password) {
    var userOpt = userRepository.findByEmail(email);
    if (userOpt.isEmpty() || !BCrypt.checkpw(password, userOpt.get().getPasswordHash())) {
      String body = "<html><body><main class='center'><div class='card'><h2>Invalid credentials</h2>"
                  + "<p><a href='/login.html'>Back to login</a></p></div></main></body></html>";
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).contentType(MediaType.TEXT_HTML).body(body);
    }
    User u = userOpt.get();
    String token = UUID.randomUUID().toString();
    u.setToken(token);
    userRepository.save(u);
    String body = "<html><body><main class='center'><div class='card'><h2>Welcome, " + escapeHtml(u.getName())
                + "</h2><p>You are logged in.</p><p>Access from mobile: keep this token safe:<br><code>" + token
                + "</code></p></div></main></body></html>";
    return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(body);
  }

  // small helper (very simple)
  private String escapeHtml(String s) {
    return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
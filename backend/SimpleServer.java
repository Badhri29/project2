package simpleauth;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class SimpleServer {
  // UPDATE these to match your MySQL
  private static final String DB_URL = "jdbc:mysql://localhost:3306/simple_auth?useSSL=false&serverTimezone=UTC";
  private static final String DB_USER = "YOUR_DB_USER";
  private static final String DB_PASS = "YOUR_DB_PASSWORD";

  private static final Map<String,String> sessions = new ConcurrentHashMap<>(); // sid -> email

  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
    server.createContext("/", new RootHandler());
    server.createContext("/login", new LoginHandler());
    server.createContext("/register", new RegisterHandler());
    server.createContext("/dashboard", new DashboardHandler());
    server.createContext("/logout", new LogoutHandler());
    server.createContext("/css", new StaticHandler("css"));
    server.setExecutor(Executors.newCachedThreadPool());
    System.out.println("Server running on http://localhost:8080/");
    server.start();
  }

  // Serve root -> redirect to /login
  static class RootHandler implements HttpHandler {
    public void handle(HttpExchange ex) throws IOException {
      redirect(ex, "/login");
    }
  }

  // Serve static files under project root folder (web files are in parent folder)
  static class StaticHandler implements HttpHandler {
    private final String folder;
    StaticHandler(String folder) { this.folder = folder; }
    public void handle(HttpExchange ex) throws IOException {
      String path = ex.getRequestURI().getPath();
      File f = new File("."+path).getCanonicalFile();
      if (!f.exists() || !f.getPath().contains(new File(folder).getCanonicalPath())) {
        send404(ex);
        return;
      }
      byte[] content = Files.readAllBytes(f.toPath());
      String type = path.endsWith(".css") ? "text/css" : "application/octet-stream";
      send(ex, 200, content, type);
    }
  }

  // LOGIN
  static class LoginHandler implements HttpHandler {
    public void handle(HttpExchange ex) throws IOException {
      if ("GET".equalsIgnoreCase(ex.getRequestMethod())) {
        serveFile(ex, "login.html");
        return;
      }
      if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
        Map<String,String> form = parseForm(ex);
        String email = form.getOrDefault("email","").trim().toLowerCase();
        String password = form.getOrDefault("password","");
        if (email.isEmpty() || password.isEmpty()) {
          redirect(ex, "/login?error=fill");
          return;
        }
        try (Connection c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
          PreparedStatement ps = c.prepareStatement("SELECT name,password_hash FROM users WHERE email = ?");
          ps.setString(1, email);
          ResultSet rs = ps.executeQuery();
          if (!rs.next() || !verifyPassword(password, rs.getString("password_hash"))) {
            redirect(ex, "/login?error=invalid");
            return;
          }
          // create session
          String sid = UUID.randomUUID().toString();
          sessions.put(sid, email);
          Headers h = ex.getResponseHeaders();
          h.add("Set-Cookie", "SID="+sid+"; Path=/; HttpOnly");
          redirect(ex, "/dashboard");
        } catch (SQLException e) {
          e.printStackTrace();
          redirect(ex, "/login?error=server");
        }
      } else send404(ex);
    }
  }

  // REGISTER
  static class RegisterHandler implements HttpHandler {
    public void handle(HttpExchange ex) throws IOException {
      if ("GET".equalsIgnoreCase(ex.getRequestMethod())) {
        serveFile(ex, "register.html");
        return;
      }
      if ("POST".equalsIgnoreCase(ex.getRequestMethod())) {
        Map<String,String> form = parseForm(ex);
        String name = form.getOrDefault("name","").trim();
        String email = form.getOrDefault("email","").trim().toLowerCase();
        String password = form.getOrDefault("password","");
        if (name.isEmpty() || email.isEmpty() || password.isEmpty()) {
          redirect(ex, "/register?error=fill");
          return;
        }
        try (Connection c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
          PreparedStatement check = c.prepareStatement("SELECT id FROM users WHERE email = ?");
          check.setString(1, email);
          ResultSet rs = check.executeQuery();
          if (rs.next()) {
            redirect(ex, "/register?error=exists");
            return;
          }
          String hash = hashPassword(password);
          PreparedStatement ins = c.prepareStatement("INSERT INTO users (name,email,password_hash) VALUES (?, ?, ?)");
          ins.setString(1, name);
          ins.setString(2, email);
          ins.setString(3, hash);
          ins.executeUpdate();
          // create session
          String sid = UUID.randomUUID().toString();
          sessions.put(sid, email);
          ex.getResponseHeaders().add("Set-Cookie", "SID="+sid+"; Path=/; HttpOnly");
          redirect(ex, "/dashboard");
        } catch (SQLException e) {
          e.printStackTrace();
          redirect(ex, "/register?error=server");
        }
      } else send404(ex);
    }
  }

  // DASHBOARD
  static class DashboardHandler implements HttpHandler {
    public void handle(HttpExchange ex) throws IOException {
      String sid = getCookie(ex, "SID");
      if (sid == null || !sessions.containsKey(sid)) {
        redirect(ex, "/login");
        return;
      }
      String email = sessions.get(sid);
      try (Connection c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
        PreparedStatement ps = c.prepareStatement("SELECT name FROM users WHERE email = ?");
        ps.setString(1, email);
        ResultSet rs = ps.executeQuery();
        String name = email;
        if (rs.next()) name = rs.getString("name");
        String html = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>" +
                      "<link rel='stylesheet' href='/css/styles.css'><title>Dashboard</title></head><body><main class='center'><div class='card'>" +
                      "<h2>Welcome, "+escapeHtml(name)+"!</h2><p>This is your dashboard.</p><ul><li>Account: "+escapeHtml(email)+"</li><li>Example item: Hello world</li></ul>" +
                      "<a class='small-link' href='/logout'>Logout</a></div></main></body></html>";
        send(ex, 200, html.getBytes(StandardCharsets.UTF_8), "text/html; charset=utf-8");
      } catch (SQLException e) {
        e.printStackTrace();
        redirect(ex, "/login");
      }
    }
  }

  // LOGOUT
  static class LogoutHandler implements HttpHandler {
    public void handle(HttpExchange ex) throws IOException {
      String sid = getCookie(ex, "SID");
      if (sid != null) sessions.remove(sid);
      Headers h = ex.getResponseHeaders();
      h.add("Set-Cookie", "SID=deleted; Path=/; Max-Age=0");
      redirect(ex, "/login");
    }
  }

  // ---------------- utilities ----------------
  static void send404(HttpExchange ex) throws IOException { send(ex, 404, "<h1>Not found</h1>".getBytes(), "text/html"); }
  static void redirect(HttpExchange ex, String location) throws IOException {
    Headers h = ex.getResponseHeaders();
    h.add("Location", location);
    ex.sendResponseHeaders(302, -1);
    ex.close();
  }
  static void send(HttpExchange ex, int code, byte[] body, String contentType) throws IOException {
    Headers h = ex.getResponseHeaders();
    h.add("Content-Type", contentType);
    ex.sendResponseHeaders(code, body.length);
    try (OutputStream os = ex.getResponseBody()) { os.write(body); }
  }
  static void serveFile(HttpExchange ex, String filename) throws IOException {
    File f = new File(filename);
    if (!f.exists()) { send404(ex); return; }
    byte[] bytes = Files.readAllBytes(f.toPath());
    send(ex, 200, bytes, "text/html; charset=utf-8");
  }

  static Map<String,String> parseForm(HttpExchange ex) throws IOException {
    String raw = new BufferedReader(new InputStreamReader(ex.getRequestBody(), StandardCharsets.UTF_8))
      .lines().collect(Collectors.joining("\n"));
    Map<String,String> m = new HashMap<>();
    for (String pair : raw.split("&")) {
      if (pair.isEmpty()) continue;
      String[] kv = pair.split("=",2);
      String k = URLDecoder.decode(kv[0], "UTF-8");
      String v = kv.length>1 ? URLDecoder.decode(kv[1], "UTF-8") : "";
      m.put(k,v);
    }
    return m;
  }

  static String getCookie(HttpExchange ex, String name) {
    List<String> cookies = ex.getRequestHeaders().get("Cookie");
    if (cookies==null) return null;
    for (String line : cookies) {
      for (String c : line.split(";")) {
        String[] kv = c.trim().split("=",2);
        if (kv.length==2 && kv[0].equals(name)) return kv[1];
      }
    }
    return null;
  }

  // password hashing: SHA-256 with per-user random salt (demo-only). Not bcrypt but ok for learning.
  static String hashPassword(String password) {
    try {
      byte[] salt = new byte[12];
      new Random().nextBytes(salt);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(salt);
      byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(digest);
    } catch (Exception e) { throw new RuntimeException(e); }
  }
  static boolean verifyPassword(String password, String stored) {
    try {
      String[] parts = stored.split(":");
      byte[] salt = Base64.getDecoder().decode(parts[0]);
      byte[] expected = Base64.getDecoder().decode(parts[1]);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(salt);
      byte[] got = md.digest(password.getBytes(StandardCharsets.UTF_8));
      return Arrays.equals(expected, got);
    } catch (Exception e) { return false; }
  }

  static String escapeHtml(String s) {
    if (s==null) return "";
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
  }
}
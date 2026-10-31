import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Register extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            Connection con = DriverManager.getConnection("jdbc:mysql://localhost/app");
            String user = request.getParameter("username");
            String pass = request.getParameter("password"); // $ Source
            String email = request.getParameter("email");
            Statement stmt = con.createStatement();
            stmt.executeUpdate("INSERT into users(username, password, email) values ('" + user + "','" + pass + "','" + email + "')"); // $ Alert
            // Not a write of the password.
            stmt.executeQuery("SELECT * FROM users WHERE username='" + user + "'");
        } catch (SQLException ex) {
            throw new ServletException(ex);
        }
    }

    public void updatePassword(Connection con, String user, String newPassword) throws SQLException {
        PreparedStatement ps = con.prepareStatement("UPDATE users SET password = ? WHERE username = ?");
        ps.setString(1, newPassword); // $ Alert
        ps.setString(2, user);
        ps.executeUpdate();
    }

    public void updateHashedPassword(Connection con, String user, String newPassword) throws Exception {
        PreparedStatement ps = con.prepareStatement("UPDATE users SET password = ? WHERE username = ?");
        ps.setString(1, hashPassword(newPassword));
        ps.setString(2, user);
        ps.executeUpdate();
    }

    public void updateLastLogin(Connection con, String password) throws SQLException {
        PreparedStatement ps = con.prepareStatement("UPDATE users SET last_login = ? WHERE password = ?");
        ps.setString(1, "today");
        ps.setString(2, password);
        ps.executeUpdate();
    }

    public void insertConflictPredicateOnly(Connection con, String password) throws SQLException {
        PreparedStatement ps = con.prepareStatement(
                "INSERT INTO users(password) VALUES (?) ON CONFLICT(password) DO UPDATE SET last_login = 1 WHERE password = ?");
        ps.setString(1, "safe");
        ps.setString(2, password);
        ps.executeUpdate();
    }

    public void concatenatedPredicateOnly(Statement stmt, String password) throws SQLException {
        stmt.executeUpdate("UPDATE users SET last_login = 1 WHERE password = '" + password + "'");
    }

    public void concatenatedPasswordUpdate(Statement stmt, String password) throws SQLException {
        stmt.executeUpdate("UPDATE users SET password = '" + password + "' WHERE username = 'alice'"); // $ Alert
    }

    public void updateDecryptedPassword(Connection con) throws SQLException {
        String password = getPassword();
        String cleartext = password; // $ Source
        PreparedStatement ps = con.prepareStatement("INSERT INTO users(password) VALUES (?)");
        ps.setString(1, decryptPassword(cleartext)); // $ Alert
        ps.executeUpdate();
    }

    public void insertInlineDecryptedPassword(Connection con) throws SQLException {
        PreparedStatement ps = con.prepareStatement("INSERT INTO users(password) VALUES (?)");
        ps.setString(1, decryptPassword(getPassword())); // $ Alert
        ps.executeUpdate();
    }

    public void updateAssignedHash(Connection con, String input) throws Exception {
        String password = hashPassword(input);
        PreparedStatement ps = con.prepareStatement("UPDATE users SET password = ? WHERE username = ?");
        ps.setString(1, password);
        ps.setString(2, "alice");
        ps.executeUpdate();
    }

    public boolean checkPassword(Connection con, String user, String password) throws SQLException {
        PreparedStatement ps = con.prepareStatement("SELECT 1 FROM users WHERE username = ? AND password = ?");
        ps.setString(1, user);
        ps.setString(2, password);
        return ps.executeQuery().next();
    }

    private static String hashPassword(String password) throws Exception {
        return new String(MessageDigest.getInstance("SHA-256").digest(password.getBytes()));
    }

    private static String getPassword() {
        return "password";
    }

    private static String decryptPassword(String encryptedValue) {
        return encryptedValue;
    }
}

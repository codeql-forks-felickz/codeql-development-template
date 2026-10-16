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

    public boolean checkPassword(Connection con, String user, String password) throws SQLException {
        PreparedStatement ps = con.prepareStatement("SELECT 1 FROM users WHERE username = ? AND password = ?");
        ps.setString(1, user);
        ps.setString(2, password);
        return ps.executeQuery().next();
    }

    private static String hashPassword(String password) throws Exception {
        return new String(MessageDigest.getInstance("SHA-256").digest(password.getBytes()));
    }
}

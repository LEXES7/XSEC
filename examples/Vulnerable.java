// Deliberately vulnerable Java sample, for testing XSEC.
// Run: xsec scan examples/Vulnerable.java

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Vulnerable {

    static final String API_KEY = "super_secret_value_123";  // fake, for testing

    void runCommand(String userInput) throws Exception {
        Runtime.getRuntime().exec("ping " + userInput);  // command injection
    }

    ResultSet lookup(Connection conn, String name) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");  // SQLi
    }

    Object load(ObjectInputStream in) throws Exception {
        return in.readObject();  // unsafe deserialization (stream created elsewhere)
    }

    Object loadDirect(java.io.InputStream raw) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(raw);  // unsafe deserialization
        return ois.readObject();
    }

    byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // weak hash
        return md.digest(data);
    }
}

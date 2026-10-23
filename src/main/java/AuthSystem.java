import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class AuthSystem {
    private static final String DB_FILE = "users.txt";

    public static String generateSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] saltBytes = new byte[16];
        sr.nextBytes(saltBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : saltBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String hashPassword(String password, String salt) {
        try {
            String combined = password + salt;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(combined.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    public static void registerUser(String username, String password) {
        File file = new File(DB_FILE);
        
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length > 0 && parts[0].equals(username)) {
                        System.out.println("[-] Error: User '" + username + "' already exists.");
                        return;
                    }
                }
            } catch (IOException e) {
                System.out.println("[-] Error reading database.");
                return;
            }
        }

        String salt = generateSalt();
        String passwordHash = hashPassword(password, salt);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file, true))) {
            writer.write(username + ":" + salt + ":" + passwordHash);
            writer.newLine();
            System.out.println("[+] Success: User '" + username + "' registered successfully.");
        } catch (IOException e) {
            System.out.println("[-] Error saving user data.");
        }
    }

    public static boolean loginUser(String username, String password) {
        File file = new File(DB_FILE);
        if (!file.exists()) {
            System.out.println("[-] Error: No registered users found.");
            return false;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 3) {
                    String storedUser = parts[0];
                    String salt = parts[1];
                    String storedHash = parts[2];

                    if (storedUser.equals(username)) {
                        String inputHash = hashPassword(password, salt);
                        if (inputHash.equals(storedHash)) {
                            System.out.println("[+] Success: Welcome back, '" + username + "'! Login verified.");
                            return true;
                        } else {
                            System.out.println("[-] Error: Invalid password.");
                            return false;
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("[-] Error reading database.");
        }

        System.out.println("[-] Error: User '" + username + "' not found.");
        return false;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n=== Secure Authentication System ===");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option (1-3): ");
            
            String choice = scanner.nextLine().trim();

            if (choice.equals("1")) {
                System.out.print("Enter username: ");
                String u = scanner.nextLine().trim();
                System.out.print("Enter password: ");
                String p = scanner.nextLine().trim();
                if (!u.isEmpty() && !p.isEmpty()) {
                    registerUser(u, p);
                } else {
                    System.out.println("[-] Username and password cannot be empty.");
                }
            } else if (choice.equals("2")) {
                System.out.print("Enter username: ");
                String u = scanner.nextLine().trim();
                System.out.print("Enter password: ");
                String p = scanner.nextLine().trim();
                if (!u.isEmpty() && !p.isEmpty()) {
                    loginUser(u, p);
                } else {
                    System.out.println("[-] Username and password cannot be empty.");
                }
            } else if (choice.equals("3")) {
                System.out.println("Exiting program.");
                break;
            } else {
                System.out.println("[-] Invalid option. Please choose 1, 2, or 3.");
            }
        }
        scanner.close();
    }
}
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.spec.KeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

class SecretVault {
    private static final int BUFFER_SIZE = 64 * 1024;
    private byte[] key;
    private final String hidDir;
    private final String cfgFilePath;

    public SecretVault(String masterpwd) {
        this.hidDir = System.getProperty("user.home") + "/.new/";
        this.cfgFilePath = System.getProperty("user.home") + "/.vaul/";
        generateKey(masterpwd);
    }

    public void addFile(String path, boolean encrypt) throws Exception {
        File file = new File(path);
        if (encrypt) {
            String filenameWithExt = file.getName() + ".aes";
            String vaultPath = hidDir + filenameWithExt;
            encryptFile(path, vaultPath);
        } else {
            Files.copy(file.toPath(), Paths.get(hidDir, file.getName()), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public void delFile(int index) throws Exception {
        File[] files = new File(hidDir).listFiles();
        if (files != null && index >= 0 && index < files.length) {
            String filenameWithExt = files[index].getName();
            String vaultPath = hidDir + filenameWithExt;
            if (filenameWithExt.endsWith(".aes")) {
                decryptFile(vaultPath, filenameWithExt.substring(0, filenameWithExt.length() - 4));
                Files.deleteIfExists(Paths.get(vaultPath));
            } else {
                Files.copy(files[index].toPath(), Paths.get(hidDir, filenameWithExt), StandardCopyOption.REPLACE_EXISTING);
                Files.deleteIfExists(files[index].toPath());
            }
        } else {
            System.out.println("Invalid index or vault is empty.");
        }
    }

    public void listFiles() {
        File[] files = new File(hidDir).listFiles();
        if (files == null || files.length == 0) {
            System.out.println("\nVault is empty!!!");
            return;
        }
        int maxlen = Arrays.stream(files).map(File::getName).mapToInt(String::length).max().orElse(0);
        System.out.println();
        System.out.println("-".repeat(maxlen + 10));
        System.out.println("index\t| files");
        System.out.println("-".repeat(maxlen + 10));
        for (int i = 0; i < files.length; i++) {
            System.out.println(i + "\t| " + files[i].getName());
            System.out.println("-".repeat(maxlen + 10));
        }
    }

    private void generateKey(String masterpwd) {
        try {
            byte[] salt = {(byte)0xb9, 0x1f, 0x7c, 0x7d, 0x27, (byte)0x93, (byte)0xa1, (byte)0x96,
                    (byte)0xeb, 0x15, 0x34, 0x04, (byte)0x88, (byte)0xf3, (byte)0xdf, 0x05};
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(masterpwd.toCharArray(), salt, 100000, 256);
            SecretKey tmp = factory.generateSecret(spec);
            key = tmp.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void encryptFile(String inputFilePath, String outputFilePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
                if (encryptedBytes != null) {
                    fos.write(encryptedBytes);
                }
            }
            byte[] encryptedBytes = cipher.doFinal();
            if (encryptedBytes != null) {
                fos.write(encryptedBytes);
            }
        }
    }

    private void decryptFile(String inputFilePath, String outputFilePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
                if (decryptedBytes != null) {
                    fos.write(decryptedBytes);
                }
            }
            byte[] decryptedBytes = cipher.doFinal();
            if (decryptedBytes != null) {
                fos.write(decryptedBytes);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Welcome to the secret vault!!!");
        Scanner scanner = new Scanner(System.in);
        String cfgFilePath = System.getProperty("user.home") + "/.vaul";
        String masterpwd;
        if (new File(cfgFilePath).exists()) {
            System.out.print("Enter your Master Password : ");
            masterpwd = scanner.nextLine();
            SecretVault vault = new SecretVault(masterpwd);
            System.out.println("Welcome Back");
        } else {
            System.out.print("Create a Master Password : ");
            masterpwd = scanner.nextLine();
            SecretVault vault = new SecretVault(masterpwd);
            Files.writeString(Paths.get(cfgFilePath), masterpwd);
            try {
                Files.createDirectories(Paths.get(vault.hidDir));
            } catch (FileAlreadyExistsException e) {
                // Ignore if the directory already exists
            }
            System.out.println("Welcome");
        }

        int choice = 0;
        while (choice != 4) {
            System.out.println("\nEnter 1 to hide a file");
            System.out.println("Enter 2 to unhide a file");
            System.out.println("Enter 3 to view hidden files");
            System.out.println("Enter 4 to Exit");
            System.out.println("Enter 5 to Reset the vault and delete all of its contents\n");

            System.out.print("Enter your choice : ");
            try {
                choice = Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Unknown value!");
                continue;
            }

            SecretVault vault = new SecretVault(masterpwd);

            if (choice == 1) {
                System.out.println("Tip: Drag and Drop the file");
                System.out.print("Enter the path of the file to hide : ");
                String filePath = scanner.nextLine();
                filePath = filePath.replace("\\", "");
                if (filePath.endsWith(" ")) {
                    filePath = filePath.substring(0, filePath.length() - 1);
                }
                if (Files.exists(Paths.get(filePath))) {
                    System.out.print("Do you want to encrypt the file? (Y or N) : ");
                    String encOrNot = scanner.nextLine();
                    boolean encrypt = encOrNot.equalsIgnoreCase("y");
                    System.out.println("\nAdding file to the vault...");
                    vault.addFile(filePath, encrypt);
                    System.out.println("\nFile successfully added to the vault");
                    System.out.println("You can now delete the original file if you want");
                } else {
                    System.out.println("\nFile does not exist!");
                }

            } else if (choice == 2) {
                vault.listFiles();
                System.out.print("\nEnter the index of the file from view hidden files : ");
                try {
                    int fileIndex = Integer.parseInt(scanner.nextLine());
                    vault.delFile(fileIndex);
                    System.out.println("\nFile unhidden successfully");
                    System.out.println("The file will be present in " + vault.hidDir);
                } catch (NumberFormatException e) {
                    System.out.println("\nInvalid index!");
                }

            } else if (choice == 3) {
                vault.listFiles();

            } else if (choice == 5) {
                System.out.print("\nDo you really want to delete and reset the vault? (Y or N) : ");
                String confirm = scanner.nextLine();
                if (confirm.equalsIgnoreCase("y")) {
                    System.out.print("\nEnter the password to confirm : ");
                    String pwdCheck = scanner.nextLine();
                    if (Files.readString(Paths.get(cfgFilePath)).equals(pwdCheck)) {
                        System.out.println("Removing and resetting all data...");
                        Files.deleteIfExists(Paths.get(cfgFilePath));
                        File[] files = new File(vault.hidDir).listFiles();
                        if (files != null) {
                            for (File file : files) {
                                Files.deleteIfExists(file.toPath());
                            }
                        }
                        Files.deleteIfExists(Paths.get(vault.hidDir));
                        System.out.println("\nReset done. Thank You");
                        System.exit(0);
                    } else {
                        System.out.println("\nWrong Master Password!");
                        System.out.println("Closing program now...");
                        System.exit(1);
                    }
                } else if (confirm.equalsIgnoreCase("n")) {
                    System.out.println("\nHappy for that");
                } else {
                    System.out.println("Type Y or N");
                }

            } else if (choice == 4) {
                System.out.println("Exiting program...");
                System.exit(0);

            } else {
                System.out.println("Invalid choice!");
            }
        }
    }
}

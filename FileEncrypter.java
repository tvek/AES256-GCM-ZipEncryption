import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileInputStream;

class FileAES256GCMEncrypter {
    private final int GCM_TAG_LENGTH = 16;
    private SecretKey key;
    byte[] IV;

    public FileAES256GCMEncrypter(SecretKey key, byte[] IV) {
        this.key = key;
        this.IV = IV;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return decryptedText;
    }

    public static Map<SecretKey, byte[]> generatePrivateKey() {
        int AES_KEY_SIZE = 256;
        int GCM_IV_LENGTH = 12;

        Map<SecretKey, byte[]> result = new HashMap<>();
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey key = keyGenerator.generateKey();
            byte[] IV = new byte[GCM_IV_LENGTH];
            keyGenerator.init(AES_KEY_SIZE);
            // Generate Key
            SecureRandom random = new SecureRandom();
            random.nextBytes(IV);
            result.put(key, IV);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

}

public class FileEncrypter {
    public static byte[] readFile(String filename) {
        byte[] bytes = new byte[1];
        try {
            File file = new File(filename);
            bytes = new byte[(int) file.length()];

            try (FileInputStream fis = new FileInputStream(file)) {
                fis.read(bytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bytes;
    }

    public static void writeFile(String filename, byte[] data) {
        try {
            try (FileOutputStream fos = new FileOutputStream(filename)) {
                fos.write(data);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        // String plainTextString = "This is a plain text which need to be encrypted by
        // Java AES 256 GCM Encryption Algorithm";
        // byte[] plainText = plainTextString.getBytes();
        String inputFile = "hellothomas.zip";
        byte[] plainText = readFile(inputFile);

        Map<SecretKey, byte[]> result = FileAES256GCMEncrypter.generatePrivateKey();
        SecretKey key;
        byte[] IV;
        for (Map.Entry<SecretKey, byte[]> entry : result.entrySet()) {
            key = entry.getKey();
            IV = entry.getValue();
            FileAES256GCMEncrypter encrypter = new FileAES256GCMEncrypter(key, IV);
            System.out.println("Original Text : " + plainText);

            byte[] cipherText = encrypter.encrypt(plainText);
            System.out.println("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));
            writeFile("encrypted" + inputFile, cipherText);

            byte[] decryptedText = encrypter.decrypt(cipherText);
            writeFile("decrypted" + inputFile, decryptedText);
            System.out.println("DeCrypted Text : " + decryptedText);
        }
    }

}

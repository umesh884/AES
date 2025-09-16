import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESExample {

    private static final SecureRandom RANDOM = new SecureRandom();

    // --- Key generation utilities ---

    /**
     * Generate a random AES key.
     * @param keySizeBits 128, 192, or 256 (256 requires JRE with unlimited crypto enabled in some old JREs)
     */
    public static SecretKey generateRandomKey(int keySizeBits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(keySizeBits, RANDOM);
        return kg.generateKey();
    }

    /**
     * Derive AES key from password using PBKDF2WithHmacSHA256.
     * @param password password
     * @param salt 16-byte salt
     * @param iterations PBKDF2 iterations (e.g., 100_000)
     * @param keySizeBits desired key size in bits (128 or 256)
     */
    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt, int iterations, int keySizeBits) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keySizeBits);
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // --- AES-GCM (recommended) ---
    // We'll prepend the IV to the ciphertext (IV || ciphertext) and Base64 encode the whole.

    /**
     * Encrypt using AES-GCM (recommended). Returns Base64( iv || ciphertext ).
     * GCM tag length is 128 bits.
     */
    public static String encryptGCM(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[12]; // 12 bytes is the recommended IV length for GCM
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final int TAG_LENGTH_BIT = 128;
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // combine iv + ciphertext
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    /**
     * Decrypt Base64( iv || ciphertext ) produced by encryptGCM.
     */
    public static String decryptGCM(String base64IvAndCiphertext, SecretKey key) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(base64IvAndCiphertext);

        byte[] iv = new byte[12];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);

        byte[] ciphertext = new byte[ivAndCiphertext.length - iv.length];
        System.arraycopy(ivAndCiphertext, iv.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final int TAG_LENGTH_BIT = 128;
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, "UTF-8");
    }

    // --- AES-CBC (for reference only, not authenticated) ---
    // We'll prepend IV to ciphertext as IV || ciphertext.

    public static String encryptCBC(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[16]; // 16 bytes for AES block size
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    public static String decryptCBC(String base64IvAndCiphertext, SecretKey key) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(base64IvAndCiphertext);

        byte[] iv = new byte[16];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);

        byte[] ciphertext = new byte[ivAndCiphertext.length - iv.length];
        System.arraycopy(ivAndCiphertext, iv.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);

        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, "UTF-8");
    }

    // --- Utilities ---
    public static String toBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static SecretKey fromBase64(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // --- Example usage in main ---
    public static void main(String[] args) throws Exception {
        String plaintext = "This is a secret message 👀";

        // 1) Generate a random AES-256 key (use 128 if you prefer)
        SecretKey key = generateRandomKey(256);
        System.out.println("Random Key (Base64): " + toBase64(key));

        // AES-GCM (recommended)
        String gcmCiphertext = encryptGCM(plaintext, key);
        System.out.println("GCM Ciphertext (Base64 iv||ct): " + gcmCiphertext);
        String gcmDecrypted = decryptGCM(gcmCiphertext, key);
        System.out.println("GCM Decrypted: " + gcmDecrypted);

        // AES-CBC (reference only - not authenticated!)
        String cbcCiphertext = encryptCBC(plaintext, key);
        System.out.println("CBC Ciphertext (Base64 iv||ct): " + cbcCiphertext);
        String cbcDecrypted = decryptCBC(cbcCiphertext, key);
        System.out.println("CBC Decrypted: " + cbcDecrypted);

        // 2) Derive key from password using PBKDF2
        char[] password = "CorrectHorseBatteryStaple".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        int iterations = 100_000;
        SecretKey derived = deriveKeyFromPassword(password, salt, iterations, 256);
        System.out.println("Derived Key (Base64): " + toBase64(derived));
        String encryptedWithDerived = encryptGCM("secret using password", derived);
        System.out.println("Encrypted with derived key: " + encryptedWithDerived);
        String decryptedWithDerived = decryptGCM(encryptedWithDerived, derived);
        System.out.println("Decrypted with derived key: " + decryptedWithDerived);
    }
}

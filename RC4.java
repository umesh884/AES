import java.util.*;

public class RC4Example {

    private byte[] S = new byte[256];
    private int i, j;

    // --- Key Scheduling Algorithm (KSA) ---
    public RC4Example(byte[] key) {
        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + (S[i] & 0xFF) + (key[i % key.length] & 0xFF)) & 0xFF;
            swap(S, i, j);
        }
        this.i = 0;
        this.j = 0;
    }

    // --- PRGA: generate next keystream byte ---
    private byte nextKeyByte() {
        i = (i + 1) & 0xFF;
        j = (j + (S[i] & 0xFF)) & 0xFF;
        swap(S, i, j);
        int t = ((S[i] & 0xFF) + (S[j] & 0xFF)) & 0xFF;
        return S[t];
    }

    // --- Encrypt/Decrypt (same operation) ---
    public byte[] encryptDecrypt(byte[] data) {
        byte[] output = new byte[data.length]()

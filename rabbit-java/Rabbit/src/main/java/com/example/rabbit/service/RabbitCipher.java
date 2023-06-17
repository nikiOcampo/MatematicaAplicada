package com.example.rabbit.service;

import com.example.rabbit.domain.RabbitRequest;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;

@Component
public class RabbitCipher {

    private RabbitCipher() {
    }

    private static final int A0 = 0x4D34D34D;
    private static final int A1 = 0xD34D34D3;
    private static final int A2 = 0x34D34D34;
    private static final int A3 = 0x4D34D34D;
    private static final int A4 = 0xD34D34D3;
    private static final int A5 = 0x34D34D34;
    private static final int A6 = 0x4D34D34D;
    private static final int A7 = 0xD34D34D3;

    private static final int[] A = {A0, A1, A2, A3, A4, A5, A6, A7};

    private static final int[] X = new int[8];
    private static final int[] C = new int[8];
    private static int b;

    private static final int[] G = new int[8];
    private static final byte[] S = new byte[16];

    private static final int BLOCK_LENGTH = 16;
    //private static final BigInteger IV = new BigInteger("0xA6EB561AD2F41727", 16);

    public static void setupKey(byte[] key) {
        if (key.length < BLOCK_LENGTH) {
            throw new IllegalArgumentException("key must be greater or equal to 16 bytes or 128 bits");
        }

        int[] k = new int[8];
        for (int i = 0; i < 8; i++) {
            k[i] = (key[2 * i + 1] << 8) | (key[2 * i] & 0xFF);
        }

        for (int j = 0; j < 8; j++) {
            if ((j % 2 == 0)) {
                X[j] = (k[(j + 1) % 8] << 16) | (k[j] & 0xFFFF);
                C[j] = (k[(j + 4) % 8] << 16) | (k[(j + 5) % 8] & 0xFFFF);
            } else {
                X[j] = (k[(j + 5) % 8] << 16) | (k[(j + 4) % 8] & 0xFFFF);
                C[j] = (k[j] << 16) | (k[(j + 1) % 8] & 0xFFFF);
            }
        }

        for (int i = 0; i < 4; i++) {
            counterUpdate();
            nextState();
        }

        reinitializeCounters();

        //setIV();
    }

    public static void counterUpdate() {
        long temp;
        for (int i = 0; i < 8; i++) {
            temp = (C[i] & 0xFFFFFFFFL) + (A[i] & 0xFFFFFFFFL) + b;
            b = (int) (temp >>> 32);
            C[i] = (int) (temp & 0xFFFFFFFFL);
        }
    }

    public static void nextState() {
        for (int i = 0; i < 8; i++) {
            G[i] = g(X[i], C[i]);
        }

        X[0] = G[0] + rotate(G[7], 16) + rotate(G[6], 16);
        X[1] = G[1] + rotate(G[0], 8) + G[7];
        X[2] = G[2] + rotate(G[1], 16) + rotate(G[0], 16);
        X[3] = G[3] + rotate(G[2], 8) + G[1];
        X[4] = G[4] + rotate(G[3], 16) + rotate(G[2], 16);
        X[5] = G[5] + rotate(G[4], 8) + G[3];
        X[6] = G[6] + rotate(G[5], 16) + rotate(G[4], 16);
        X[7] = G[7] + rotate(G[6], 8) + G[5];

    }

    private static void reinitializeCounters() {
        for (int i = 0; i < 8; i++) {
            C[i] = C[i] ^ X[(i + 4) % 8];
        }
    }

    private static int g(int u, int v) {
        long square = u + v & 0xFFFFFFFFL;
        square *= square;
        return (int) (square ^ square >>> 32);
    }

    private static int rotate(int value, int shift) {
        return value << shift | value >>> (32 - shift);
    }

    public static void nextBlock() {
        nextState();

        int x = X[0] ^ X[5] >>> 16;
        S[0] = (byte) x;
        S[1] = (byte) (x >> 8);

        x = X[0] >>> 16 ^ X[3];
        S[2] = (byte) x;
        S[3] = (byte) (x >> 8);

        x = X[2] ^ X[7] >>> 16;
        S[4] = (byte) x;
        S[5] = (byte) (x >> 8);

        x = X[2] >> 16 ^ X[5];
        S[6] = (byte) x;
        S[7] = (byte) (x >> 8);

        x = X[4] ^ X[1] >>> 16;
        S[8] = (byte) x;
        S[9] = (byte) (x >> 8);

        x = X[4] >>> 16 ^ X[7];
        S[10] = (byte) x;
        S[11] = (byte) (x >> 8);

        x = X[6] ^ X[3] >>> 16;
        S[12] = (byte) x;
        S[13] = (byte) (x >> 8);

        x = X[6] >>> 16 ^ X[1];
        S[14] = (byte) x;
        S[15] = (byte) (x >> 8);
    }

    public static byte[] crypt(byte[] message) {
        for (int i = 0; i < message.length; i++) {
            if (i % BLOCK_LENGTH == 0) {
                nextBlock();
            }
            message[i] ^= S[i % BLOCK_LENGTH];
        }
        return message;
    }
  
    public static void cryptByPythonFile(String path, RabbitRequest request) throws IOException {
        String pythonScriptPath = path + "rabbit.py";
        String picturePath = path + request.getPicture();
        String option = "-" + request.getOption().name().toLowerCase();
        String key = request.getKey();
        String iv = request.getIv();

        ProcessBuilder processBuilder = new ProcessBuilder("python", pythonScriptPath, picturePath, option, key, iv);
        processBuilder.directory(new File(path));

        Process process = processBuilder.start();
    }


}

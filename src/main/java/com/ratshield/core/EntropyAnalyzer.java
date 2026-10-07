package com.ratshield.core;

public final class EntropyAnalyzer {
    private EntropyAnalyzer() {
    }

    public static double shannon(byte[] data, int offset, int length) {
        if (length <= 0) {
            return 0.0;
        }
        int[] counts = new int[256];
        int end = Math.min(data.length, offset + length);
        int total = 0;
        for (int i = Math.max(0, offset); i < end; i++) {
            counts[data[i] & 0xFF]++;
            total++;
        }
        if (total == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double p = (double) count / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public static double shannon(byte[] data) {
        return shannon(data, 0, data.length);
    }

    public static boolean looksPacked(double entropy) {
        return entropy >= 7.2;
    }
}

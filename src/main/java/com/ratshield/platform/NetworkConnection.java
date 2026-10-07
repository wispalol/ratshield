package com.ratshield.platform;

import java.time.Instant;

/**
 * A single observed network connection.
 *
 * @param pid           owning process id
 * @param protocol      tcp or udp
 * @param localAddress  local bind address
 * @param localPort     local port
 * @param remoteAddress remote address (or wildcard for listeners)
 * @param remotePort    remote port
 * @param state         connection state as reported by the OS
 * @param hostname      reverse DNS name, resolved lazily and cached
 */
public record NetworkConnection(long pid, String protocol, String localAddress, int localPort,
                                String remoteAddress, int remotePort, String state, String hostname,
                                Instant observedAt) {

    public boolean isListener() {
        return remotePort <= 0 || "*".equals(remoteAddress) || "0.0.0.0".equals(remoteAddress)
                || "::".equals(remoteAddress) || remoteAddress.isBlank();
    }

    public boolean isExternal(String localSubnetPrefix) {
        if (isListener()) {
            return false;
        }
        String addr = remoteAddress;
        if (addr.startsWith("127.") || addr.equals("::1") || addr.startsWith("fe80:")) {
            return false;
        }
        if (addr.startsWith("192.168.") || addr.startsWith("10.") || addr.startsWith("169.254.")) {
            return false;
        }
        if (addr.startsWith("172.")) {
            int second = 0;
            int dot = addr.indexOf('.', 4);
            try {
                second = Integer.parseInt(addr.substring(4, dot < 0 ? addr.length() : dot));
            } catch (NumberFormatException ignored) {
                // leave as external
            }
            if (second >= 16 && second <= 31) {
                return false;
            }
        }
        if (addr.startsWith("fc") || addr.startsWith("fd") || addr.startsWith("::ffff:192.168.")
                || addr.startsWith("::ffff:10.") || addr.startsWith("::ffff:172.")) {
            return false;
        }
        return true;
    }

    public String endpoint() {
        return remoteAddress + ":" + remotePort;
    }
}

package com.ratshield.platform;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class WindowsNetworkProviderImpl implements WindowsNetworkProvider {
    private record DnsEntry(String host, Instant at) {
    }

    private final Map<String, DnsEntry> dnsCache = new ConcurrentHashMap<>();
    private final ExecutorService resolver = Executors.newFixedThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "ratshield-dns");
        thread.setDaemon(true);
        return thread;
    });
    private volatile String lastError = "";

    @Override
    public List<NetworkConnection> connections() {
        List<NetworkConnection> out = new ArrayList<>();
        Instant now = Instant.now();
        collectInto(out, now, "tcp");
        collectInto(out, now, "udp");
        return out;
    }

    private void collectInto(List<NetworkConnection> out, Instant now, String protocol) {
        CommandRunner.Result result = CommandRunner.run(Duration.ofSeconds(12), "netstat", "-ano", "-p", protocol);
        if (result.unavailable()) {
            lastError = "netstat unavailable";
            return;
        }
        if (!result.ok()) {
            lastError = "netstat failed: " + result.stderr().trim();
            return;
        }
        for (String line : result.lines()) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("Active") || trimmed.startsWith("Proto")
                    || trimmed.startsWith("协议")) {
                continue;
            }
            String[] parts = trimmed.split("\\s+");
            if (parts.length < 4) {
                continue;
            }
            String proto = parts[0].toLowerCase(Locale.ROOT);
            if (!proto.equals("tcp") && !proto.equals("udp")) {
                continue;
            }
            Endpoint local = parseEndpoint(parts[1]);
            if (local == null) {
                continue;
            }
            String state = "";
            String remotePart;
            String pidPart;
            if (parts.length >= 5) {
                remotePart = parts[2];
                state = parts[3];
                pidPart = parts[4];
            } else {
                remotePart = parts[2];
                pidPart = parts[3];
            }
            Endpoint remote = parseEndpoint(remotePart);
            long pid;
            try {
                pid = Long.parseLong(pidPart);
            } catch (NumberFormatException e) {
                continue;
            }
            out.add(new NetworkConnection(pid, proto, local.address(), local.port(),
                    remote == null ? "" : remote.address(), remote == null ? -1 : remote.port(),
                    state, cachedHost(remote == null ? "" : remote.address()), now));
        }
    }

    private record Endpoint(String address, int port) {
    }

    private static Endpoint parseEndpoint(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        int colon = value.lastIndexOf(':');
        if (colon < 0) {
            return new Endpoint(value, -1);
        }
        String address = value.substring(0, colon);
        String portPart = value.substring(colon + 1);
        int port;
        if (portPart.equals("*")) {
            port = -1;
        } else {
            try {
                port = Integer.parseInt(portPart);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (address.isEmpty()) {
            address = "0.0.0.0";
        }
        return new Endpoint(address, port);
    }

    private String cachedHost(String address) {
        if (address == null || address.isEmpty() || address.equals("*")) {
            return "";
        }
        DnsEntry entry = dnsCache.get(address);
        if (entry != null && Duration.between(entry.at(), Instant.now()).toMinutes() < 30) {
            return entry.host();
        }
        if (entry == null || Duration.between(entry.at(), Instant.now()).toMinutes() >= 30) {
            dnsCache.put(address, new DnsEntry(entry == null ? "" : entry.host(), Instant.now().minusSeconds(31)));
            resolver.execute(() -> {
                try {
                    String host = InetAddress.getByName(address).getCanonicalHostName();
                    dnsCache.put(address, new DnsEntry(host == null ? "" : host, Instant.now()));
                } catch (UnknownHostException e) {
                    dnsCache.put(address, new DnsEntry(address, Instant.now()));
                }
            });
        }
        return entry == null ? "" : entry.host();
    }

    @Override
    public Optional<String> hostname(String address) {
        if (address == null || address.isEmpty()) {
            return Optional.empty();
        }
        DnsEntry entry = dnsCache.get(address);
        if (entry != null && !entry.host().equals(address)) {
            return Optional.of(entry.host());
        }
        cachedHost(address);
        return Optional.empty();
    }

    @Override
    public List<String> diagnostics() {
        return lastError.isBlank() ? List.of() : List.of(lastError);
    }

    public void shutdown() {
        resolver.shutdownNow();
    }
}

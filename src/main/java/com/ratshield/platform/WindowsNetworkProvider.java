package com.ratshield.platform;

import java.util.List;
import java.util.Optional;

/**
 * Platform boundary for read-only network connection inspection.
 *
 * <p>The default implementation parses {@code netstat -ano}, which ships with every supported
 * Windows version. Hostname resolution is best effort and never blocks the caller.</p>
 */
public interface WindowsNetworkProvider {
    List<NetworkConnection> connections();

    Optional<String> hostname(String address);

    List<String> diagnostics();
}

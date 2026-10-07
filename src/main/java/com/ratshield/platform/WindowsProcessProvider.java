package com.ratshield.platform;

import java.util.List;
import java.util.Optional;

/**
 * Platform boundary for process enumeration, inspection and termination.
 *
 * <p>The default implementation reads the live process table through
 * {@link ProcessHandle#allProcesses()} and enriches it with Win32 process metadata obtained
 * from {@code Get-CimInstance}. It never launches, injects into, or otherwise manipulates a
 * process unless {@link #terminate(long)} is explicitly requested by the user.</p>
 */
public interface WindowsProcessProvider {
    List<ProcessSnapshot> listProcesses();

    List<ProcessSnapshot> listProcesses(boolean enrich);

    Optional<ProcessSnapshot> snapshot(long pid);

    String owner(long pid);

    boolean terminate(long pid);

    List<String> diagnostics();
}

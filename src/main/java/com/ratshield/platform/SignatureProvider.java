package com.ratshield.platform;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Platform boundary for code-signature inspection.
 *
 * <p>Implementations must never execute the file being inspected. The default Windows
 * implementation first determines whether the PE image carries an Authenticode certificate
 * table (pure Java, no execution) and, when a definitive verdict is required, asks the
 * Windows {@code Get-AuthenticodeSignature} cmdlet for the platform verdict.</p>
 */
public interface SignatureProvider {
    SignatureInfo verify(Path file);

    default Map<Path, SignatureInfo> verifyAll(Collection<Path> files) {
        return files.stream().collect(java.util.stream.Collectors.toMap(f -> f, this::verify, (a, b) -> a));
    }

    /**
     * Warm the signature cache for many files at once so later {@link #verify(Path)} calls
     * are served from cache instead of spawning one process per file.
     */
    default void prefetch(List<Path> files) {
    }

    default List<String> diagnostics() {
        return List.of();
    }
}

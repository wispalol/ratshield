package com.ratshield.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PeInfo {
    public record Section(String name, int virtualAddress, long virtualSize, long rawSize, double entropy) {
    }

    private final boolean pe32Plus;
    private final int machine;
    private final int subsystem;
    private final boolean dll;
    private final Instant compileTime;
    private final int entryPointRva;
    private final List<Section> sections;
    private final Map<String, List<String>> imports;
    private final boolean certificateTablePresent;
    private final long certificateSize;
    private final long overlaySize;
    private final long fileSize;
    private final List<String> importedDlls;

    public PeInfo(boolean pe32Plus, int machine, int subsystem, boolean dll, Instant compileTime,
                  int entryPointRva, List<Section> sections, Map<String, List<String>> imports,
                  boolean certificateTablePresent, long certificateSize, long overlaySize, long fileSize) {
        this.pe32Plus = pe32Plus;
        this.machine = machine;
        this.subsystem = subsystem;
        this.dll = dll;
        this.compileTime = compileTime;
        this.entryPointRva = entryPointRva;
        this.sections = Collections.unmodifiableList(new ArrayList<>(sections));
        this.imports = Collections.unmodifiableMap(new LinkedHashMap<>(imports));
        this.importedDlls = Collections.unmodifiableList(new ArrayList<>(imports.keySet()));
        this.certificateTablePresent = certificateTablePresent;
        this.certificateSize = certificateSize;
        this.overlaySize = overlaySize;
        this.fileSize = fileSize;
    }

    public boolean isPe32Plus() {
        return pe32Plus;
    }

    public int machine() {
        return machine;
    }

    public int subsystem() {
        return subsystem;
    }

    public boolean isDll() {
        return dll;
    }

    public Instant compileTime() {
        return compileTime;
    }

    public int entryPointRva() {
        return entryPointRva;
    }

    public List<Section> sections() {
        return sections;
    }

    public Map<String, List<String>> imports() {
        return imports;
    }

    public List<String> importedDlls() {
        return importedDlls;
    }

    public boolean isCertificateTablePresent() {
        return certificateTablePresent;
    }

    public long certificateSize() {
        return certificateSize;
    }

    public long overlaySize() {
        return overlaySize;
    }

    public long fileSize() {
        return fileSize;
    }

    public boolean isLikelyPacked() {
        int executableSections = 0;
        int packedSections = 0;
        for (Section s : sections) {
            if (s.name().startsWith(".text") || s.name().startsWith(".code") || s.name().startsWith("UPX")
                    || s.name().startsWith(".aspack") || s.name().contains("pack")) {
                executableSections++;
            }
            if (s.entropy() >= 7.2) {
                packedSections++;
            }
        }
        if (packedSections >= 2) {
            return true;
        }
        for (Section s : sections) {
            if ((s.name().startsWith("UPX") || s.name().toLowerCase().contains("packed")) && s.entropy() > 6.5) {
                return true;
            }
        }
        return executableSections > 0 && overlaySize > 0 && overlaySize > fileSize / 4;
    }

    public double maxSectionEntropy() {
        double max = 0;
        for (Section s : sections) {
            max = Math.max(max, s.entropy());
        }
        return max;
    }

    public String machineName() {
        return switch (machine) {
            case 0x014c -> "x86";
            case 0x8664 -> "x64";
            case 0x01c4 -> "ARM";
            case 0xAA64 -> "ARM64";
            default -> String.format("0x%04X", machine);
        };
    }

    public String subsystemName() {
        return switch (subsystem) {
            case 1 -> "Native";
            case 2 -> "Windows GUI";
            case 3 -> "Windows Console";
            case 10 -> "EFI Application";
            default -> "Subsystem " + subsystem;
        };
    }
}

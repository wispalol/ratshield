package com.ratshield.core;

public enum FileType {
    PE_EXECUTABLE,
    PE_LIBRARY,
    PE_INSTALLER,
    NATIVE_EXECUTABLE,
    SCRIPT,
    SHORTCUT,
    INSTALLER,
    ARCHIVE,
    DOCUMENT,
    IMAGE,
    MEDIA,
    DATA,
    UNKNOWN;

    public boolean isExecutable() {
        return this == PE_EXECUTABLE || this == PE_LIBRARY || this == PE_INSTALLER
                || this == NATIVE_EXECUTABLE || this == SCRIPT || this == SHORTCUT || this == INSTALLER;
    }
}

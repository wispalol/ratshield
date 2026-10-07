package com.ratshield.core;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class FileClassifier {
    public record Classification(FileType type, String extension, String declaredExtension,
                                 boolean doubleExtension, boolean rightToLeftOverride,
                                 String trueExtension, boolean executableMagic, boolean archiveMagic) {
    }

    public static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            "exe", "scr", "com", "pif", "bat", "cmd", "dll", "sys", "ocx", "cpl", "msi", "msp",
            "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "jnlp",
            "reg", "lnk", "appx", "msix", "msixbundle", "xll", "acm", "ax", "drv", "efi",
            "chm", "rgs", "sct", "uif", "iso", "img", "url", "desktop");

    private static final List<String> DECEPTIVE_EXTENSIONS = List.of(
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "pdf", "doc", "docx", "xls", "xlsx",
            "ppt", "pptx", "txt", "rtf", "csv", "mp3", "mp4", "avi", "mkv", "zip", "html", "htm",
            "xml", "json", "svg", "ico", "tif", "tiff", "epub", "apk");

    private static final List<String> REAL_EXTENSIONS = List.of(
            "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "jar",
            "msi", "dll", "lnk", "reg", "wsf", "wsh", "cpl", "msix");

    private FileClassifier() {
    }

    public static Classification classify(String fileName, byte[] header) {
        String lower = fileName == null ? "" : fileName.toLowerCase(Locale.ROOT);
        String extension = extensionOf(lower);
        String trueExtension = extension;
        boolean doubleExtension = false;
        int lastDot = lower.lastIndexOf('.');
        if (lastDot > 0 && lastDot < lower.length() - 1) {
            String last = lower.substring(lastDot + 1);
            int prevDot = lower.lastIndexOf('.', lastDot - 1);
            if (prevDot > 0) {
                String declared = lower.substring(prevDot + 1, lastDot);
                if (DECEPTIVE_EXTENSIONS.contains(declared) && REAL_EXTENSIONS.contains(last)) {
                    doubleExtension = true;
                    trueExtension = last;
                } else if (EXECUTABLE_EXTENSIONS.contains(last) && !EXECUTABLE_EXTENSIONS.contains(declared)
                        && declared.length() >= 2 && !declared.equals("tar")) {
                    doubleExtension = true;
                    trueExtension = last;
                }
            }
        }
        if (extension != null && EXECUTABLE_EXTENSIONS.contains(extension)) {
            trueExtension = extension;
        }
        boolean rtl = fileName != null && fileName.indexOf('\u202E') >= 0;
        boolean executableMagic = false;
        boolean archiveMagic = false;
        FileType type = FileType.UNKNOWN;

        if (header != null && header.length >= 4) {
            if (header[0] == 'M' && header[1] == 'Z') {
                executableMagic = true;
                type = FileType.PE_EXECUTABLE;
            } else if (header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
                executableMagic = true;
                type = FileType.NATIVE_EXECUTABLE;
            } else if (header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4) {
                archiveMagic = true;
                type = FileType.ARCHIVE;
            } else if (header[0] == '7' && header[1] == 'z' && (header[2] & 0xFF) == 0xBC) {
                archiveMagic = true;
                type = FileType.ARCHIVE;
            } else if (header[0] == 'R' && header[1] == 'a' && header[2] == 'r' && header[3] == '!') {
                archiveMagic = true;
                type = FileType.ARCHIVE;
            } else if ((header[0] & 0xFF) == 0x1F && (header[1] & 0xFF) == 0x8B) {
                archiveMagic = true;
                type = FileType.ARCHIVE;
            } else if (header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F') {
                type = FileType.DOCUMENT;
            } else if (header[0] == (byte) 0xD0 && header[1] == (byte) 0xCF && header[2] == 0x11) {
                type = FileType.INSTALLER;
            } else if (header[0] == (byte) 0x4C && header[1] == 0 && header[2] == 0 && header[3] == 1) {
                type = FileType.SHORTCUT;
            } else if (header[0] == 'M' && header[1] == 'S' && header[2] == 'C' && header[3] == 'F') {
                type = FileType.ARCHIVE;
                archiveMagic = true;
            } else if (header.length >= 8 && header[0] == (byte) 0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G') {
                type = FileType.IMAGE;
            } else if (header[0] == (byte) 0xFF && header[1] == (byte) 0xD8 && header[2] == (byte) 0xFF) {
                type = FileType.IMAGE;
            } else if (header[0] == 'G' && header[1] == 'I' && header[2] == 'F') {
                type = FileType.IMAGE;
            } else if (header[0] == 'B' && header[1] == 'M') {
                type = FileType.IMAGE;
            } else if (header.length >= 12 && header[4] == 'f' && header[5] == 't' && header[6] == 'y' && header[7] == 'p') {
                type = FileType.MEDIA;
            }
        }

        String textPrefix = header == null ? "" : new String(header, 0, Math.min(header.length, 512), StandardCharsets.ISO_8859_1);
        if (type == FileType.UNKNOWN && textPrefix.startsWith("#!")) {
            type = FileType.SCRIPT;
            executableMagic = true;
        }

        if (type == FileType.UNKNOWN || type == FileType.PE_EXECUTABLE) {
            if (extension != null) {
                type = switch (extension) {
                    case "exe", "scr", "com", "pif" -> FileType.PE_EXECUTABLE;
                    case "dll", "sys", "ocx", "xll" -> FileType.PE_LIBRARY;
                    case "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg" -> FileType.SCRIPT;
                    case "lnk" -> FileType.SHORTCUT;
                    case "msi", "msp", "msix", "msixbundle", "appx" -> FileType.INSTALLER;
                    case "jar", "zip", "7z", "rar", "gz", "tar", "cab", "iso" -> FileType.ARCHIVE;
                    case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "epub" -> FileType.DOCUMENT;
                    case "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tif", "tiff" -> FileType.IMAGE;
                    case "mp3", "mp4", "avi", "mkv", "wav", "flac", "mov", "webm" -> FileType.MEDIA;
                    default -> type == FileType.UNKNOWN ? FileType.DATA : type;
                };
            }
        }

        if (doubleExtension && type != FileType.ARCHIVE) {
            type = switch (trueExtension) {
                case "exe", "scr", "com", "pif" -> FileType.PE_EXECUTABLE;
                case "bat", "cmd", "ps1", "vbs", "js", "hta", "wsf", "reg" -> FileType.SCRIPT;
                case "lnk" -> FileType.SHORTCUT;
                case "msi" -> FileType.INSTALLER;
                case "jar" -> FileType.ARCHIVE;
                default -> type;
            };
        }

        if (executableMagic && (type == FileType.UNKNOWN || type == FileType.DATA)) {
            type = FileType.PE_EXECUTABLE;
        }

        return new Classification(type, extension, extension, doubleExtension, rtl, trueExtension,
                executableMagic, archiveMagic);
    }

    public static boolean isExecutableLike(Classification c) {
        if (c == null) {
            return false;
        }
        return c.type().isExecutable() || c.executableMagic() || c.doubleExtension();
    }

    public static String extensionOf(String lowerFileName) {
        int dot = lowerFileName.lastIndexOf('.');
        if (dot < 0 || dot == lowerFileName.length() - 1) {
            return "";
        }
        return lowerFileName.substring(dot + 1);
    }

    public static boolean looksLikeArchiveName(String lowerFileName) {
        String ext = extensionOf(lowerFileName);
        return ext.equals("zip") || ext.equals("jar") || ext.equals("7z") || ext.equals("rar")
                || ext.equals("gz") || ext.equals("tar") || ext.equals("cab") || ext.equals("apk");
    }

    /**
     * Detects names padded with spaces so the real extension lands past the point where
     * Explorer or a terminal truncates the visible text, e.g. {@code invoice        .exe}.
     */
    public static boolean looksSpacePadded(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return false;
        }
        java.util.regex.Matcher matcher = SPACE_PADDING.matcher(fileName);
        return matcher.find();
    }

    /**
     * Runs of whitespace that end a visible name right before the extension dot, or that
     * separate an executable extension from an otherwise harmless looking name.
     */
    private static final java.util.regex.Pattern SPACE_PADDING =
            java.util.regex.Pattern.compile("\\s{4,}\\.[A-Za-z0-9]{1,10}$|\\s{6,}\\.\\s*[A-Za-z0-9]{1,10}$");
}

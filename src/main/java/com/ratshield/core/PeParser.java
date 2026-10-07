package com.ratshield.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal, defensive PE (Portable Executable) parser used by the RATShield detection engine.
 * It never executes the file and never maps it with write access.
 */
public final class PeParser {
    private static final long MAX_MAP = Integer.MAX_VALUE - 8L;
    private static final int MAX_DLLS = 512;
    private static final int MAX_IMPORTS_PER_DLL = 4096;

    private PeParser() {
    }

    public static Optional<PeInfo> parse(Path file) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size < 64) {
                return Optional.empty();
            }
            long mapSize = Math.min(size, MAX_MAP);
            MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, mapSize);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            return Optional.of(parse(buffer, size));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    public static boolean looksLikePeHeader(byte[] header) {
        if (header == null || header.length < 64 || header[0] != 'M' || header[1] != 'Z') {
            return false;
        }
        ByteBuffer buffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        long peOffset = Integer.toUnsignedLong(buffer.getInt(0x3C));
        if (peOffset + 4 <= header.length) {
            return buffer.getInt((int) peOffset) == 0x00004550;
        }
        return true;
    }

    public static Optional<PeInfo> parse(byte[] data) {
        if (data == null || data.length < 64) {
            return Optional.empty();
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            return Optional.of(parse(buffer, data.length));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static PeInfo parse(ByteBuffer buf, long fileSize) throws IOException {
        if (u16(buf, 0) != 0x5A4D) {
            throw new IOException("missing MZ header");
        }
        long peOffset = u32(buf, 0x3C);
        if (peOffset < 0 || peOffset + 24 > buf.limit()) {
            throw new IOException("invalid e_lfanew");
        }
        int peSig = (int) u32(buf, (int) peOffset);
        if (peSig != 0x00004550) {
            throw new IOException("missing PE signature");
        }
        int coff = (int) peOffset + 4;
        int machine = u16(buf, coff);
        int numberOfSections = u16(buf, coff + 2);
        long timestamp = u32(buf, coff + 4);
        int sizeOfOptionalHeader = u16(buf, coff + 16);
        int characteristics = u16(buf, coff + 18);
        boolean dll = (characteristics & 0x2000) != 0;

        int opt = coff + 20;
        int magic = u16(buf, opt);
        boolean pe32Plus = magic == 0x20B;
        if (!pe32Plus && magic != 0x10B) {
            throw new IOException("unknown optional header magic");
        }
        int entryPoint = (int) u32(buf, opt + 16);
        int subsystem = u16(buf, opt + 68);
        int numberOfRvaAndSizes = (int) u32(buf, opt + (pe32Plus ? 108 : 92));
        int dirStart = opt + (pe32Plus ? 112 : 96);

        long certOffset = 0;
        long certSize = 0;
        if (numberOfRvaAndSizes > 4 && dirStart + 5 * 8 <= buf.limit()) {
            certOffset = u32(buf, dirStart + 4 * 8);
            certSize = u32(buf, dirStart + 4 * 8 + 4);
        }

        int sectionTable = opt + sizeOfOptionalHeader;
        List<PeInfo.Section> sections = new ArrayList<>();
        long rawEnd = 0;
        for (int i = 0; i < numberOfSections && i < 96; i++) {
            int off = sectionTable + i * 40;
            if (off + 40 > buf.limit()) {
                break;
            }
            String name = readCString(buf, off, 8).trim();
            if (name.isEmpty()) {
                name = String.format("sect%d", i);
            }
            int virtualSize = (int) u32(buf, off + 8);
            int virtualAddress = (int) u32(buf, off + 12);
            int rawSize = (int) u32(buf, off + 16);
            int rawPtr = (int) u32(buf, off + 20);
            double entropy = 0;
            if (rawPtr > 0 && rawSize > 0 && rawPtr + rawSize <= buf.limit()) {
                byte[] raw = new byte[(int) Math.min(rawSize, 8 * 1024 * 1024)];
                int readLen = (int) Math.min(raw.length, rawSize);
                ByteBuffer dup = buf.duplicate();
                dup.position(rawPtr);
                dup.get(raw, 0, readLen);
                entropy = EntropyAnalyzer.shannon(raw, 0, readLen);
            }
            sections.add(new PeInfo.Section(name, virtualAddress, virtualSize & 0xFFFFFFFFL, rawSize & 0xFFFFFFFFL, entropy));
            rawEnd = Math.max(rawEnd, (rawPtr & 0xFFFFFFFFL) + (rawSize & 0xFFFFFFFFL));
        }

        Map<String, List<String>> imports = readImports(buf, dirStart, pe32Plus, numberOfRvaAndSizes, fileSize);
        long overlay = rawEnd > 0 && rawEnd < fileSize ? fileSize - rawEnd : 0;
        boolean certPresent = certOffset > 0 && certSize > 0 && certOffset < fileSize;

        return new PeInfo(pe32Plus, machine, subsystem, dll,
                Instant.ofEpochSecond(timestamp), entryPoint, sections, imports,
                certPresent, certPresent ? certSize : 0, overlay, fileSize);
    }

    private static Map<String, List<String>> readImports(ByteBuffer buf, int dirStart, boolean pe32Plus,
                                                         int numberOfDirs, long fileSize) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        if (numberOfDirs < 2 || dirStart + 16 > buf.limit()) {
            return result;
        }
        int importRva = (int) u32(buf, dirStart + 8);
        int importSize = (int) u32(buf, dirStart + 12);
        if (importRva == 0 || importSize == 0) {
            return result;
        }
        int descriptor = rvaToOffset(buf, importRva);
        if (descriptor < 0) {
            return result;
        }
        for (int i = 0; i < MAX_DLLS; i++) {
            int off = descriptor + i * 20;
            if (off + 20 > buf.limit()) {
                break;
            }
            int originalFirstThunk = (int) u32(buf, off);
            int nameRva = (int) u32(buf, off + 12);
            int firstThunk = (int) u32(buf, off + 16);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) {
                break;
            }
            String dllName = readCString(buf, rvaToOffset(buf, nameRva), 256);
            if (dllName.isEmpty()) {
                continue;
            }
            int thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            List<String> functions = readThunks(buf, thunkRva, pe32Plus);
            result.put(dllName.toLowerCase(), functions);
        }
        return result;
    }

    private static List<String> readThunks(ByteBuffer buf, int thunkRva, boolean pe32Plus) {
        List<String> functions = new ArrayList<>();
        int thunkOffset = rvaToOffset(buf, thunkRva);
        if (thunkOffset < 0) {
            return functions;
        }
        int entrySize = pe32Plus ? 8 : 4;
        long ordinalMask = pe32Plus ? 0x8000000000000000L : 0x80000000L;
        for (int i = 0; i < MAX_IMPORTS_PER_DLL; i++) {
            int off = thunkOffset + i * entrySize;
            if (off + entrySize > buf.limit()) {
                break;
            }
            long value = pe32Plus ? u64(buf, off) : (u32(buf, off) & 0xFFFFFFFFL);
            if (value == 0) {
                break;
            }
            if ((value & ordinalMask) != 0) {
                functions.add("ordinal#" + (value & 0xFFFF));
                continue;
            }
            int nameOffset = rvaToOffset(buf, (int) value);
            if (nameOffset < 0 || nameOffset + 2 >= buf.limit()) {
                continue;
            }
            functions.add(readCString(buf, nameOffset + 2, 256));
            if (functions.size() >= MAX_IMPORTS_PER_DLL) {
                break;
            }
        }
        return functions;
    }

    private static int rvaToOffset(ByteBuffer buf, int rva) {
        if (rva <= 0) {
            return -1;
        }
        int sectionsStart = findSectionTable(buf);
        if (sectionsStart < 0) {
            return rva;
        }
        int numberOfSections = u16(buf, findCoff(buf) + 2);
        for (int i = 0; i < numberOfSections && i < 96; i++) {
            int off = sectionsStart + i * 40;
            if (off + 40 > buf.limit()) {
                break;
            }
            int va = (int) u32(buf, off + 12);
            long vsize = u32(buf, off + 8);
            long rawSize = u32(buf, off + 16);
            int rawPtr = (int) u32(buf, off + 20);
            long span = Math.max(vsize, rawSize);
            if (rva >= va && rva < va + span) {
                return rawPtr + (rva - va);
            }
        }
        return -1;
    }

    private static int findCoff(ByteBuffer buf) {
        long peOffset = u32(buf, 0x3C);
        return (int) peOffset + 4;
    }

    private static int findSectionTable(ByteBuffer buf) {
        int coff = findCoff(buf);
        int sizeOfOptionalHeader = u16(buf, coff + 16);
        return coff + 20 + sizeOfOptionalHeader;
    }

    private static String readCString(ByteBuffer buf, int offset, int max) {
        if (offset < 0 || offset >= buf.limit()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < max && offset + i < buf.limit(); i++) {
            byte b = buf.get(offset + i);
            if (b == 0) {
                break;
            }
            if (b >= 32 && b < 127) {
                sb.append((char) b);
            } else {
                return sb.toString();
            }
        }
        return sb.toString();
    }

    private static int u16(ByteBuffer buf, int off) {
        if (off < 0 || off + 2 > buf.limit()) {
            return 0;
        }
        return buf.getShort(off) & 0xFFFF;
    }

    private static long u32(ByteBuffer buf, int off) {
        if (off < 0 || off + 4 > buf.limit()) {
            return 0;
        }
        return buf.getInt(off) & 0xFFFFFFFFL;
    }

    private static long u64(ByteBuffer buf, int off) {
        if (off < 0 || off + 8 > buf.limit()) {
            return 0;
        }
        return buf.getLong(off);
    }
}

// Generated by jextract

package com.capstone4j.internal;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * struct cs_wasm_brtable {
 *     uint32_t length;
 *     uint64_t address;
 *     uint32_t default_target;
 * }
 * }
 */
public class cs_wasm_brtable {

    cs_wasm_brtable() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("length"),
        MemoryLayout.paddingLayout(4),
        capstone_h.C_LONG_LONG.withName("address"),
        capstone_h.C_INT.withName("default_target"),
        MemoryLayout.paddingLayout(4)
    ).withName("cs_wasm_brtable");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt length$LAYOUT = (OfInt)$LAYOUT.select(groupElement("length"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint32_t length
     * }
     */
    public static final OfInt length$layout() {
        return length$LAYOUT;
    }

    private static final long length$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint32_t length
     * }
     */
    public static final long length$offset() {
        return length$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint32_t length
     * }
     */
    public static int length(MemorySegment struct) {
        return struct.get(length$LAYOUT, length$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint32_t length
     * }
     */
    public static void length(MemorySegment struct, int fieldValue) {
        struct.set(length$LAYOUT, length$OFFSET, fieldValue);
    }

    private static final OfLong address$LAYOUT = (OfLong)$LAYOUT.select(groupElement("address"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint64_t address
     * }
     */
    public static final OfLong address$layout() {
        return address$LAYOUT;
    }

    private static final long address$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint64_t address
     * }
     */
    public static final long address$offset() {
        return address$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint64_t address
     * }
     */
    public static long address(MemorySegment struct) {
        return struct.get(address$LAYOUT, address$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint64_t address
     * }
     */
    public static void address(MemorySegment struct, long fieldValue) {
        struct.set(address$LAYOUT, address$OFFSET, fieldValue);
    }

    private static final OfInt default_target$LAYOUT = (OfInt)$LAYOUT.select(groupElement("default_target"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint32_t default_target
     * }
     */
    public static final OfInt default_target$layout() {
        return default_target$LAYOUT;
    }

    private static final long default_target$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint32_t default_target
     * }
     */
    public static final long default_target$offset() {
        return default_target$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint32_t default_target
     * }
     */
    public static int default_target(MemorySegment struct) {
        return struct.get(default_target$LAYOUT, default_target$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint32_t default_target
     * }
     */
    public static void default_target(MemorySegment struct, int fieldValue) {
        struct.set(default_target$LAYOUT, default_target$OFFSET, fieldValue);
    }

    /**
     * Obtains a slice of {@code arrayParam} which selects the array element at {@code index}.
     * The returned segment has address {@code arrayParam.address() + index * layout().byteSize()}
     */
    public static MemorySegment asSlice(MemorySegment array, long index) {
        return array.asSlice(layout().byteSize() * index);
    }

    /**
     * The size (in bytes) of this struct
     */
    public static long sizeof() { return layout().byteSize(); }

    /**
     * Allocate a segment of size {@code layout().byteSize()} using {@code allocator}
     */
    public static MemorySegment allocate(SegmentAllocator allocator) {
        return allocator.allocate(layout());
    }

    /**
     * Allocate an array of size {@code elementCount} using {@code allocator}.
     * The returned segment has size {@code elementCount * layout().byteSize()}.
     */
    public static MemorySegment allocateArray(long elementCount, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(elementCount, layout()));
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, Arena arena, Consumer<MemorySegment> cleanup) {
        return reinterpret(addr, 1, arena, cleanup);
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code elementCount * layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, long elementCount, Arena arena, Consumer<MemorySegment> cleanup) {
        return addr.reinterpret(layout().byteSize() * elementCount, arena, cleanup);
    }
}


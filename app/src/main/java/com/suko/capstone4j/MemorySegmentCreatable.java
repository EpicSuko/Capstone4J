package com.suko.capstone4j;

public interface MemorySegmentCreatable<T extends CapstoneArchDetails<?>> {
    // This is just a marker interface to indicate that implementing classes
    // should provide a static createFromMemorySegment method that accepts a
    // MemorySegment and returns an instance of the implementing class.
}

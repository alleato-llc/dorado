package com.alleato.dorado.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** Tests for the pure chunk-cap clamping helper (no environment access). */
class FormatTest {
    @Test
    void clampChunkCapNullIsDefault() {
        assertEquals(Format.DEFAULT_MAX_CHUNK_BYTES, Format.clampChunkCap(null));
    }

    @Test
    void clampChunkCapEmptyIsDefault() {
        assertEquals(Format.DEFAULT_MAX_CHUNK_BYTES, Format.clampChunkCap(""));
    }

    @Test
    void clampChunkCapUnparseableIsDefault() {
        assertEquals(Format.DEFAULT_MAX_CHUNK_BYTES, Format.clampChunkCap("not-a-number"));
        assertEquals(Format.DEFAULT_MAX_CHUNK_BYTES, Format.clampChunkCap("12x"));
    }

    @Test
    void clampChunkCapPlainValuePassesThrough() {
        assertEquals(1_000_000L, Format.clampChunkCap("1000000"));
    }

    @Test
    void clampChunkCapZeroClampsUpToOne() {
        assertEquals(1L, Format.clampChunkCap("0"));
    }

    @Test
    void clampChunkCapAboveCeilingClampsToHardCeiling() {
        long aboveGiB = (1L << 30) + 1;
        assertEquals(Format.MAX_CHUNK_BYTES, Format.clampChunkCap(Long.toString(aboveGiB)));
    }
}

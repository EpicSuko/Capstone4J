package com.capstone4j;

public class CapstoneInstructionDetails {

    private final int[] regsRead;
    private final int regsReadCount;
    private final int[] regsWrite;
    private final int regsWriteCount;
    private final int[] groups;
    private final int groupsCount;
    private final boolean writeback;

    CapstoneInstructionDetails(int[] regsRead, int regsReadCount, int[] regsWrite, int regsWriteCount, int[] groups, int groupsCount, boolean writeback) {
        this.regsRead = regsRead;
        this.regsReadCount = regsReadCount;
        this.regsWrite = regsWrite;
        this.regsWriteCount = regsWriteCount;
        this.groups = groups;
        this.groupsCount = groupsCount;
        this.writeback = writeback;
    }

    public int[] getRegsRead() {
        return this.regsRead;
    }

    public int getRegsReadCount() {
        return this.regsReadCount;
    }

    public int[] getRegsWrite() {
        return this.regsWrite;
    }

    public int getRegsWriteCount() {
        return this.regsWriteCount;
    }

    public int[] getGroups() {
        return this.groups;
    }

    public int getGroupsCount() {
        return this.groupsCount;
    }

    public boolean isWriteback() {
        return this.writeback;
    }
}
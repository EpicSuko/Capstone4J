package com.capstone4j;

public class CapstoneUtils {

    public static String getErrorMessage(CapstoneError error) {
        return switch (error) {
            case OK -> "No error: everything was fine";
            case MEM -> "Out-Of-Memory";
            case ARCH -> "Unsupported architecture";
            case HANDLE -> "Invalid handle";
            case CSH -> "Invalid csh argument";
            case MODE -> "Invalid/unsupported mode";
            case OPTION -> "Invalid/unsupported option";
            case DETAIL -> "Information is unavailable because detail option is OFF";
            case MEMSETUP -> "Dynamic memory management uninitialized (see CapstoneOption.MEM)";
            case VERSION -> "Unsupported version";
            case DIET -> "Access irrelevant data in \"diet\" engine";
            case SKIPDATA -> "Access irrelevant data for \"data\" instruction in SKIPDATA mode";
            case X86_ATT -> "X86 AT&T syntax is unsupported";
            case X86_INTEL -> "X86 Intel syntax is unsupported";
            case X86_MASM -> "X86 Masm syntax is unsupported";
            default -> "Unknown error";
        };
    }

    public static String getErrorMessage(int error) {
        return getErrorMessage(CapstoneError.fromValue(error));
    }
}

package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * A utility class for parsing C-style format strings and formatting values.
 * <p>
 * This class provides functionality to parse C-style format strings and format values
 * accordingly. It is used by the {@link DefaultCapstoneMemoryProvider#vsnprintf} method
 * to handle format string parsing and value formatting.
 * <p>
 * Reference : {@url https://github.com/weiss/c99-snprintf/blob/master/snprintf.c}
 */
class FormatStringParser {

    /**
     * Formats a string using a format string and variable arguments, and writes it to a buffer.
     * <p>
     * This method corresponds to the C {@code vsnprintf} function. It is used by Capstone
     * for formatting error messages and other output.
     *
     * @param str the buffer to write the formatted string to
     * @param size the size of the buffer in bytes
     * @param format the format string
     * @param ap the variable arguments pointer
     * @return the number of characters that would have been written if {@code size} had been
     *         sufficiently large, not counting the terminating null character
     */
    static int vsnprintf(MemorySegment str, long size, MemorySegment format, MemorySegment ap) {
        if (str == null || size <= 0) {
            size = 0;
        }

        StringBuilder sb = new StringBuilder();
        long offset = 0;
        while(true) {
            byte b = format.get(C_CHAR, offset++);
            if(b == 0) {
                break;
            }
            sb.append((char) b);
        }

        String formatString = sb.toString();

        char[] formatChars = formatString.toCharArray();
        int formatIndex = 0;

        boolean overflow = false;

        int flags = 0;
        FormatConv cflags = null;
        int precision = -1;
        int width = 0;

        int len = 0;

        FormatReadState state = FormatReadState.PRINT_S_DEFAULT;

        boolean out = false;

        out:
        if(!out) {
            while(formatIndex < formatChars.length && formatChars[formatIndex] != '\0') {
                switch(state) {
                    case PRINT_S_DEFAULT:
                        if(formatChars[formatIndex] == '%') {
                            state = FormatReadState.PRINT_S_FLAGS;
                        } else {
                            if(len < size - 1) {
                                str.set(ValueLayout.JAVA_BYTE, len, (byte) formatChars[formatIndex]);
                            }
                            len++;
                        }
                        formatIndex++;
                        break;
                    case PRINT_S_FLAGS:
                        switch(formatChars[formatIndex]) {
                            case '-':
                                flags |= FormatFlags.PRINT_F_MINUS.getValue();
                                formatIndex++;
                                break;
                            case '+':
                                flags |= FormatFlags.PRINT_F_PLUS.getValue();
                                formatIndex++;
                                break;
                            case ' ':
                                flags |= FormatFlags.PRINT_F_SPACE.getValue();
                                formatIndex++;
                                break;
                            case '#':
                                flags |= FormatFlags.PRINT_F_NUM.getValue();
                                formatIndex++;
                                break;
                            case '0':
                                flags |= FormatFlags.PRINT_F_ZERO.getValue();
                                formatIndex++;
                                break;
                            case '\'':
                                flags |= FormatFlags.PRINT_F_QUOTE.getValue();
                                formatIndex++;
                                break;
                            default:
                                state = FormatReadState.PRINT_S_WIDTH;
                                break;
                        }
                        break;
                    case PRINT_S_WIDTH:
                        if(isDigit(formatChars[formatIndex])) {
                            int n = charToInt(formatChars[formatIndex]);
                            if(width > (Integer.MAX_VALUE - n) / 10) {
                                overflow = true;
                                out = true;
                                break out;
                            }
                            width = 10 * width + n;
                            formatIndex++;
                        } else if(formatChars[formatIndex] == '*') {
                            Object[] args = va_arg(ap, C_INT);
                            ap = (MemorySegment) args[1];
                            width = (Integer) args[0];
                            if(width < 0) {
                                width = -width;
                                flags |= FormatFlags.PRINT_F_MINUS.getValue();
                            }
                            formatIndex++;
                            state = FormatReadState.PRINT_S_DOT;
                        } else {
                            state = FormatReadState.PRINT_S_DOT;
                        }
                        break;
                    case PRINT_S_DOT:
                        if(formatChars[formatIndex] == '.') {
                            state = FormatReadState.PRINT_S_PRECISION;
                            formatIndex++;
                        } else {
                            state = FormatReadState.PRINT_S_MOD;
                        }
                        break;
                    case PRINT_S_PRECISION:
                        if(precision == -1) {
                            precision = 0;
                        }
                        if(isDigit(formatChars[formatIndex])) {
                            int n = charToInt(formatChars[formatIndex]);
                            if(precision > (Integer.MAX_VALUE - n) / 10) {
                                overflow = true;
                                out = true;
                                break out;
                            }
                            precision = 10 * precision + n;
                            formatIndex++;
                        } else if(formatChars[formatIndex] == '*') {
                            Object[] args = va_arg(ap, C_INT);
                            ap = (MemorySegment) args[1];
                            precision = (Integer) args[0];
                            if(precision < 0) {
                                precision = -1;
                            }
                            formatIndex++;
                            state = FormatReadState.PRINT_S_MOD;
                        } else {
                            state = FormatReadState.PRINT_S_MOD;
                        }
                        break;
                    case PRINT_S_MOD:
                        switch(formatChars[formatIndex]) {
                            case 'h':
                                formatIndex++;
                                if(formatChars[formatIndex] == 'h') {
                                    formatIndex++;
                                    cflags = FormatConv.PRINT_C_CHAR;
                                } else {
                                    cflags = FormatConv.PRINT_C_SHORT;
                                }
                                break;
                            case 'l':
                                formatIndex++;
                                if(formatChars[formatIndex] == 'l') {
                                    formatIndex++;
                                    cflags = FormatConv.PRINT_C_LONG_LONG;
                                } else {
                                    cflags = FormatConv.PRINT_C_LONG;
                                }
                                break;
                            case 'L':
                                cflags = FormatConv.PRINT_C_LONG_DOUBLE;
                                formatIndex++;
                                break;
                            case 'j':
                                cflags = FormatConv.PRINT_C_INTMAX;
                                formatIndex++;
                                break;
                            case 't':
                                cflags = FormatConv.PRINT_C_PTRDIFF;
                                formatIndex++;
                                break;
                            case 'z':
                                cflags = FormatConv.PRINT_C_SIZE;
                                formatIndex++;
                                break;
                        }
                        state = FormatReadState.PRINT_S_CONV;
                        break;
                    case PRINT_S_CONV:
                        switch(formatChars[formatIndex]) {
                            case 'd': case 'i':
                                Object divalue;
                                if(cflags == null) {
                                    cflags = FormatConv.PRINT_C_INT;
                                }
                                switch(cflags) {
                                    case PRINT_C_CHAR:
                                        Object[] charResult = va_arg(ap, C_CHAR);
                                        ap = (MemorySegment) charResult[1];
                                        divalue = (byte)charResult[0];
                                        break;
                                    case PRINT_C_SHORT:
                                        Object[] shortResult = va_arg(ap, C_SHORT);
                                        ap = (MemorySegment) shortResult[1];
                                        divalue = (short)shortResult[0];
                                        break;
                                    case PRINT_C_LONG:
                                        Object[] longResult = va_arg(ap, C_LONG);
                                        ap = (MemorySegment) longResult[1];
                                        divalue = (int)longResult[0];
                                        break;
                                    case PRINT_C_LONG_LONG:
                                        Object[] longLongResult = va_arg(ap, C_LONG_LONG);
                                        ap = (MemorySegment) longLongResult[1];
                                        divalue = (long)longLongResult[0];
                                        break;
                                    case PRINT_C_LONG_DOUBLE:
                                        Object[] longDoubleResult = va_arg(ap, C_LONG_DOUBLE);
                                        ap = (MemorySegment) longDoubleResult[1];
                                        divalue = (double)longDoubleResult[0];
                                        break;
                                    case PRINT_C_INT:
                                        Object[] intResult = va_arg(ap, C_INT);
                                        ap = (MemorySegment) intResult[1];
                                        divalue = (int)intResult[0];
                                        break;
                                    default:
                                        throw new IllegalArgumentException("Unsupported cflag: " + cflags);
                                }
                                String diJavaFormat = buildJavaFormat(cflags, flags, width, precision, formatChars[formatIndex], false);
                                String diFormatted = String.format(diJavaFormat, divalue);
                                for (int i = 0; i < diFormatted.length() && len < size - 1; i++) {
                                    str.set(ValueLayout.JAVA_BYTE, len++, (byte) diFormatted.charAt(i));
                                }
                                break;
                            case 'x': case 'X':
                                flags |= FormatFlags.PRINT_F_UNSIGNED.getValue();
                                Object xvalue;
                                if(cflags == null) {
                                    cflags = FormatConv.PRINT_C_INT;
                                }
                                switch(cflags) {
                                    case PRINT_C_CHAR:
                                        Object[] charResult = va_arg(ap, C_CHAR);
                                        ap = (MemorySegment) charResult[1];
                                        xvalue = Byte.toUnsignedInt((Byte) charResult[0]);
                                        break;
                                    case PRINT_C_SHORT:
                                        Object[] shortResult = va_arg(ap, C_SHORT);
                                        ap = (MemorySegment) shortResult[1];
                                        xvalue = Short.toUnsignedInt((Short) shortResult[0]);
                                        break;
                                    case PRINT_C_LONG:
                                        Object[] longResult = va_arg(ap, C_LONG);
                                        ap = (MemorySegment) longResult[1];
                                        xvalue = Integer.toUnsignedLong((Integer) longResult[0]);
                                        break;
                                    case PRINT_C_LONG_LONG:
                                        Object[] longLongResult = va_arg(ap, C_LONG_LONG);
                                        ap = (MemorySegment) longLongResult[1];
                                        xvalue = Long.toUnsignedString((Long) longLongResult[0], 16);
                                        break;
                                    case PRINT_C_LONG_DOUBLE:
                                        throw new IllegalArgumentException("Hexadecimal format not supported for double");
                                    case PRINT_C_INT:
                                        Object[] intResult = va_arg(ap, C_INT);
                                        ap = (MemorySegment) intResult[1];
                                        xvalue = Integer.toUnsignedLong((Integer) intResult[0]);
                                        break;
                                    default:
                                        throw new IllegalArgumentException("Unsupported cflag: " + cflags);
                                }

                                String javaFormat = buildJavaFormat(cflags, flags, width, precision, formatChars[formatIndex], true);
                                
                                String formatted;
                                if (cflags == FormatConv.PRINT_C_LONG_LONG) {
                                    // For unsigned long long, we've already converted to hex string
                                    formatted = xvalue.toString();
                                } else {
                                    formatted = String.format(javaFormat, xvalue);
                                }
                                
                                // Ensure proper case for hexadecimal output
                                if (formatChars[formatIndex] == 'X') {
                                    formatted = formatted.toUpperCase();
                                }
                                
                                // Write the formatted string to the output buffer
                                for (int i = 0; i < formatted.length() && len < size - 1; i++) {
                                    str.set(ValueLayout.JAVA_BYTE, len++, (byte) formatted.charAt(i));
                                }
                                break;
                            case 'u':
                                flags |= FormatFlags.PRINT_F_UNSIGNED.getValue();
                                Object value;
                                if(cflags == null) {
                                    cflags = FormatConv.PRINT_C_INT;
                                }
                                switch(cflags) {
                                    case PRINT_C_CHAR:
                                        Object[] charResult = va_arg(ap, C_CHAR);
                                        ap = (MemorySegment) charResult[1];
                                        value = Byte.toUnsignedInt((Byte) charResult[0]);
                                        break;
                                    case PRINT_C_SHORT:
                                        Object[] shortResult = va_arg(ap, C_SHORT);
                                        ap = (MemorySegment) shortResult[1];
                                        value = Short.toUnsignedInt((Short) shortResult[0]);
                                        break;
                                    case PRINT_C_LONG:
                                        Object[] longResult = va_arg(ap, C_LONG);
                                        ap = (MemorySegment) longResult[1];
                                        value = Integer.toUnsignedLong((Integer) longResult[0]);
                                        break;
                                    case PRINT_C_LONG_LONG:
                                        Object[] longLongResult = va_arg(ap, C_LONG_LONG);
                                        ap = (MemorySegment) longLongResult[1];
                                        value = Long.toUnsignedString((Long) longLongResult[0]);
                                        break;
                                    case PRINT_C_LONG_DOUBLE:
                                        Object[] doubleResult = va_arg(ap, C_LONG_DOUBLE);
                                        ap = (MemorySegment) doubleResult[1];
                                        value = (Double) doubleResult[0];
                                        break;
                                    case PRINT_C_INT:
                                        Object[] intResult = va_arg(ap, C_INT);
                                        ap = (MemorySegment) intResult[1];
                                        value = Integer.toUnsignedLong((Integer) intResult[0]);
                                        break;
                                    default:
                                        throw new IllegalArgumentException("Unsupported cflag: " + cflags);
                                }

                                String ujavaFormat = buildJavaFormat(cflags, flags, width, precision, formatChars[formatIndex], true);
                                
                                String uformatted;
                                if (cflags == FormatConv.PRINT_C_LONG_LONG) {
                                    // For unsigned long long, we've already converted to string
                                    uformatted = value.toString();
                                } else {
                                    uformatted = String.format(ujavaFormat, value);
                                }
                                
                                for (int i = 0; i < uformatted.length() && len < size - 1; i++) {
                                    str.set(ValueLayout.JAVA_BYTE, len++, (byte) uformatted.charAt(i));
                                }
                                break;
                            case 's':
                                Object[] stringResult = va_arg(ap, C_POINTER);
                                ap = (MemorySegment) stringResult[1];
                                MemorySegment stringValue = (MemorySegment) stringResult[0];
                                len = writeString(str, size, len, stringValue, width, precision, flags);
                                break;
                            default:
                                System.out.println("FormatString: " + formatString);
                                System.out.println("FormatIndex: " + formatIndex);
                                System.out.println("FormatChars: " + formatChars[formatIndex]);
                                System.out.println("FormatCharsLength: " + formatChars.length);
                                System.out.println("FormatStringLength: " + formatString.length());
                                System.out.println("FormatChars: " + Arrays.toString(formatChars));
                                throw new IllegalArgumentException("Unsupported conversion specifier: " + formatChars[formatIndex]);
                        }

                        state = FormatReadState.PRINT_S_DEFAULT;
                        formatIndex++;
                        cflags = null;
                        flags = 0;
                        width = 0;
                        precision = -1;
                        break;
                }
            }
        }

        // out
        if(len < size) {
            str.set(ValueLayout.JAVA_BYTE, len, (byte) 0);
        } else if(size > 0) {
            str.set(ValueLayout.JAVA_BYTE, size - 1, (byte) 0);
        }

        if(overflow && len > Integer.MAX_VALUE) {
            return -1;
        }
        
        return len;
    }

    private static int writeString(MemorySegment str, long size, int len, MemorySegment stringValue, int width, int precision, int flags) {
        int padlen = 0;
        int strlen = 0;
        boolean noprecision = precision == -1;
        int offset = 0;

        try(Arena arena = Arena.ofConfined()) {
            if(stringValue == null || stringValue.equals(MemorySegment.NULL)) {
                stringValue = arena.allocateFrom("(null)");
            }
    
            for(strlen = 0; (noprecision || strlen < precision) && (byte)stringValue.get(C_CHAR, strlen) != 0; strlen++) {
                continue;
            }
    
            if((padlen = width - strlen) < 0) {
                padlen = 0;
            }
            if((flags & FormatFlags.PRINT_F_MINUS.getValue()) != 0) {
                padlen = -padlen;
            }
    
            while (padlen > 0) {
                if(len + 1 < size) {
                    str.set(C_CHAR, len, (byte) ' ');
                }
                len++;
                padlen--;
            }
    
            while((noprecision || precision-- > 0) && (byte)stringValue.get(C_CHAR, offset) != 0) {
                if(len + 1 < size) {
                    str.set(C_CHAR, len, (byte)stringValue.get(C_CHAR, offset));
                }
                len++;
                offset++;
            }
    
            while(padlen < 0) {
                if(len + 1 < size) {
                    str.set(C_CHAR, len, (byte) ' ');
                }
                len++;
                padlen++;
            }
        }

        return len;
    }

    /**
     * Builds a Java format string based on the given conversion flags, flags, width, precision, and conversion specifier.
     */
    private static String buildJavaFormat(FormatConv cflags, int flags, int width, int precision, char conv, boolean isSigned) {
        StringBuilder format = new StringBuilder("%");
        
        // Add flags
        if ((flags & FormatFlags.PRINT_F_MINUS.getValue()) != 0) format.append('-');
        if ((flags & FormatFlags.PRINT_F_PLUS.getValue()) != 0) format.append('+');
        if ((flags & FormatFlags.PRINT_F_SPACE.getValue()) != 0) format.append(' ');
        if ((flags & FormatFlags.PRINT_F_ZERO.getValue()) != 0) format.append('0');
        if ((flags & FormatFlags.PRINT_F_NUM.getValue()) != 0) format.append('#');

        // Add width
        if (width > 0) format.append(width);

        // Add precision
        if (precision >= 0) format.append('.').append(precision);

        // Handle special cases for Java format specifiers
        switch (conv) {
            case 'u': // unsigned decimal
                if (cflags == FormatConv.PRINT_C_LONG_LONG && isSigned) {
                    // For unsigned long long, we've already converted to string
                    return format.toString(); // Return as-is since we've already converted to string
                }
                format.append('d');
                break;
            case 'x': case 'X': // hexadecimal
                format.append(conv);
                break;
            case 'd': case 'i': // signed decimal
                format.append('d');
                break;
            case 'f': case 'F': // floating point
            case 'e': case 'E': // scientific notation
            case 'g': case 'G': // general format
                format.append(conv);
                break;
            case 's': // string
            case 'c': // character
                format.append(conv);
                break;
            default:
                throw new IllegalArgumentException("Unsupported conversion specifier: " + conv);
        }
        
        return format.toString();
    }

    /**
     * Extracts the next argument from a va_list.
     */
    private static Object[] va_arg(MemorySegment ap, ValueLayout layout) {
        // Get the current address and read the value
        Object value;
        if (layout == ValueLayout.JAVA_INT) {
            value = ap.get(ValueLayout.JAVA_INT, 0);
        } else if (layout == ValueLayout.JAVA_LONG) {
            value = ap.get(ValueLayout.JAVA_LONG, 0);
        } else if (layout == ValueLayout.JAVA_DOUBLE) {
            value = ap.get(ValueLayout.JAVA_DOUBLE, 0);
        } else if (layout == ValueLayout.JAVA_FLOAT) {
            value = ap.get(ValueLayout.JAVA_FLOAT, 0);
        } else if (layout == ValueLayout.ADDRESS) {
            value = ap.get(ValueLayout.ADDRESS, 0);
        } else if(layout == ValueLayout.JAVA_BYTE) {
            value = ap.get(ValueLayout.JAVA_BYTE, 0);
        } else if(layout == ValueLayout.JAVA_SHORT) {
            value = ap.get(ValueLayout.JAVA_SHORT, 0);
        } else if(layout == ValueLayout.JAVA_CHAR) {
            value = ap.get(ValueLayout.JAVA_CHAR, 0);
        } else if(layout == C_POINTER) {
            value = ap.get(C_POINTER, 0);
        } else {
            throw new IllegalArgumentException("Unsupported value layout: " + layout);
        }
        
        // Create the updated pointer
        MemorySegment updatedAp = ap.asSlice(layout.byteSize());
        
        return new Object[] { value, updatedAp };
    }

    /**
     * Converts a character digit to its integer value.
     */
    private static int charToInt(char c) {
        if(!isDigit(c)) {
            throw new IllegalArgumentException("Character is not a digit: " + c);
        }
        return c - '0';
    }

    /**
     * Checks if a character is a digit.
     */
    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /**
     * Enumeration of conversion flags for formatting.
     */
    private enum FormatConv {
        PRINT_C_CHAR,
        PRINT_C_SHORT,
        PRINT_C_LONG,
        PRINT_C_LONG_LONG,
        PRINT_C_LONG_DOUBLE,
        PRINT_C_SIZE,
        PRINT_C_PTRDIFF,
        PRINT_C_INTMAX,
        PRINT_C_INT;
    }

    /**
     * Enumeration of format reading states.
     */
    private enum FormatReadState {
        PRINT_S_DEFAULT,
        PRINT_S_FLAGS,
        PRINT_S_WIDTH,
        PRINT_S_DOT,
        PRINT_S_PRECISION,
        PRINT_S_MOD,
        PRINT_S_CONV
    }

    /**
     * Enumeration of format flags.
     */
    private enum FormatFlags {
        PRINT_F_MINUS(1 << 0),
        PRINT_F_PLUS(1 << 1),
        PRINT_F_SPACE(1 << 2),
        PRINT_F_NUM(1 << 3),
        PRINT_F_ZERO(1 << 4),
        PRINT_F_QUOTE(1 << 5),
        PRINT_F_UPPER(1 << 6),
        PRINT_F_UNSIGNED(1 << 7),
        PRINT_F_TYPE_G(1 << 8),
        PRINT_F_TYPE_E(1 << 9);

        private int value;

        private FormatFlags(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }
} 
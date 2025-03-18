package com.capstone4j.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

public class NativeUtils {
 
    /**
     * The minimum length a prefix for a file has to have according to {@link File#createTempFile(String, String)}}.
     */
    private static final int MIN_PREFIX_LENGTH = 3;
    public static final String NATIVE_FOLDER_PATH_PREFIX = "nativeutils";
    private static final int MAX_RETRIES = 5;

    /**
     * Temporary directory which will contain the DLLs.
     */
    private static File temporaryDir;

    /**
     * Private constructor - this class will never be instanced
     */
    private NativeUtils() {
    }

    /**
     * Loads library from current JAR archive
     * 
     * The file from JAR is copied into system temporary directory and then loaded. The temporary file is deleted after
     * exiting.
     * Method uses String as filename because the pathname is "abstract", not system-dependent.
     * 
     * @param path The path of file inside JAR as absolute path (beginning with '/'), e.g. /package/File.ext
     * @throws IOException If temporary file creation or read/write operation fails
     * @throws IllegalArgumentException If source file (param path) does not exist
     * @throws IllegalArgumentException If the path is not absolute or if the filename is shorter than three characters
     * (restriction of {@link File#createTempFile(java.lang.String, java.lang.String)}).
     * @throws FileNotFoundException If the file could not be found inside the JAR.
     */
    public static void loadLibraryFromJar(String path) throws IOException {
 
        if (null == path || !path.startsWith("/")) {
            throw new IllegalArgumentException("The path has to be absolute (start with '/').");
        }
 
        // Obtain filename from path
        String[] parts = path.split("/");
        String filename = (parts.length > 1) ? parts[parts.length - 1] : null;
 
        // Check if the filename is okay
        if (filename == null || filename.length() < MIN_PREFIX_LENGTH) {
            throw new IllegalArgumentException("The filename has to be at least 3 characters long.");
        }
 
        // Create a unique temporary directory for this run
        if (temporaryDir == null) {
            temporaryDir = createTempDirectory(NATIVE_FOLDER_PATH_PREFIX + "_" + UUID.randomUUID().toString().replace("-", ""));
            temporaryDir.deleteOnExit();
        }

        // Add a unique suffix to avoid conflicts
        String uniqueFilename = filename + "_" + UUID.randomUUID().toString().replace("-", "");
        File temp = new File(temporaryDir, uniqueFilename);

        // Copy the library to the temporary file
        try (InputStream is = NativeUtils.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new FileNotFoundException("File " + path + " was not found inside JAR.");
            }
            Files.copy(is, temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            temp.delete();
            throw e;
        }

        // Load the library with retry logic
        IOException lastException = null;
        for (int retry = 0; retry < MAX_RETRIES; retry++) {
            try {
                System.load(temp.getAbsolutePath());
                // If we get here, the library was loaded successfully
                return;
            } catch (UnsatisfiedLinkError e) {
                if (e.getMessage().contains("Access is denied")) {
                    // Wait a bit before retrying
                    try {
                        Thread.sleep(100 * (retry + 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                    // Try with a new file
                    uniqueFilename = filename + "_" + UUID.randomUUID().toString().replace("-", "");
                    temp = new File(temporaryDir, uniqueFilename);
                    try (InputStream is = NativeUtils.class.getResourceAsStream(path)) {
                        if (is == null) {
                            throw new FileNotFoundException("File " + path + " was not found inside JAR.");
                        }
                        Files.copy(is, temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    }
                } else {
                    // Not an access issue, rethrow
                    throw e;
                }
            } catch (Exception e) {
                lastException = new IOException("Failed to load library on attempt " + (retry + 1), e);
            }
        }
        
        // If we get here, all retries failed
        if (lastException != null) {
            throw lastException;
        } else {
            throw new IOException("Failed to load library after " + MAX_RETRIES + " attempts");
        }
    }

    private static File createTempDirectory(String prefix) throws IOException {
        String tempDir = System.getProperty("java.io.tmpdir");
        
        // Try multiple times to create a directory
        for (int i = 0; i < MAX_RETRIES; i++) {
            File generatedDir = new File(tempDir, prefix + "_" + System.nanoTime());
            
            if (generatedDir.mkdir()) {
                return generatedDir;
            }
            
            // Wait a bit before retrying
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        throw new IOException("Failed to create temp directory after " + MAX_RETRIES + " attempts");
    }
}

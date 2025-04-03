# Capstone4J

Capstone4J is a Java binding for the [Capstone](https://github.com/capstone-engine/capstone) disassembly framework. It provides a pure Java interface to the powerful Capstone engine, allowing Java applications to disassemble machine code across multiple architectures. Built using Java 24's Foreign Function & Memory API, it offers native performance while maintaining Java's safety and ease of use.

## About Capstone

Capstone is a lightweight multi-platform, multi-architecture disassembly framework. Capstone4J brings this powerful framework to the Java ecosystem, providing:

- A type-safe Java API for all Capstone features
- Efficient memory management through Java's Foreign Memory API

## Prerequisites

- Java Development Kit (JDK) 22 or later
- Gradle (included in the project)
- Capstone C library version 6 (currently only Windows DLL is provided)

## Features

- Full support for multiple architectures:
  - x86 (16/32/64-bit)
  - ARM (32/64-bit)
  - AArch64
- Efficient memory management through Java's Foreign Memory API
- Native interop using Foreign Function & Memory API
- Comprehensive instruction details and metadata
- Support for all Capstone features and options
- Safe native memory handling
- Automatic resource cleanup through try-with-resources

## Building the Project

To build the project, run:

```bash
./gradlew build
```

On Windows:
```bash
gradlew.bat build
```

## Usage Example

```java
import com.suko.capstone4j.Capstone;
import com.suko.capstone4j.CapstoneHandle;
import com.suko.capstone4j.CapstoneHandleOptions;
import com.suko.capstone4j.CapstoneInstruction;
import com.suko.capstone4j.CapstoneOption;
import com.suko.capstone4j.CapstoneOptionValue;
import com.suko.capstone4j.CapstoneX86Details;
import com.suko.capstone4j.CapstoneX86Details.X86Encoding;

public class Example {
    public static void main(String[] args) {
        try {
            // Initialize Capstone
            Capstone.initialize();
            System.out.println("Capstone version: " + Capstone.getVersion());

            // Example x86_64 code
            byte[] code = new byte[] {
                0x55, 0x48, (byte)0x8b, 0x05, (byte)0xb8, (byte)0x13, 0x00, 0x00
            };

            // Create handle with custom options
            try (CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64)) {
                // Enable detailed instruction information
                handle.setOption(CapstoneOption.DETAIL, new CapstoneOptionValue[] { CapstoneOptionValue.ON });

                long runtimeAddress = 0x1000;
                int offset = 0;
                final int length = code.length;

                while (offset < length) {
                    int maxBytesToRead = Math.min(15, length - offset);
                    byte[] subData = Arrays.copyOfRange(code, offset, offset + maxBytesToRead);
                    CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);
                    
                    // Print basic instruction info
                    System.out.printf("\n%016X  %s %s\n", 
                        instruction.getAddress(), 
                        instruction.getMnemonic(), 
                        instruction.getOpStr());
                    System.out.println("Instruction size: " + instruction.getSize());
                    System.out.println("Instruction bytes: " + Arrays.toString(instruction.getBytes()));

                    if (instruction.getDetails() != null) {
                        // Register access information
                        System.out.println("Registers read count: " + instruction.getRegAccess().getRegsReadCount());
                        System.out.println("Registers read: " + Arrays.toString(instruction.getRegAccess().getRegsRead()));
                        System.out.println("Registers written count: " + instruction.getRegAccess().getRegsWriteCount());
                        System.out.println("Registers written: " + Arrays.toString(instruction.getRegAccess().getRegsWrite()));
                        
                        // Architecture-specific details
                        CapstoneX86Details x86Details = instruction.getDetails();
                        System.out.println("Groups count: " + x86Details.getGroupsCount());
                        System.out.println("Groups: " + Arrays.toString(x86Details.getGroups()));
                        
                        // Print register names
                        for (int regId : instruction.getRegAccess().getRegsRead()) {
                            System.out.println("Reg read: " + handle.getRegName(regId));
                        }
                        for (int regId : instruction.getRegAccess().getRegsWrite()) {
                            System.out.println("Reg write: " + handle.getRegName(regId));
                        }
                        
                        // Print instruction and group names
                        System.out.println("Instruction name: " + handle.getInsnName(instruction.getId()));
                        for (int groupId : x86Details.getGroups()) {
                            System.out.println("Group: " + handle.getGroupName(groupId));
                        }

                        // Print operand information
                        System.out.println("OP Count: " + x86Details.getArchDetails().getOpCount());
                        System.out.println("Operands:");
                        for (int i = 0; i < x86Details.getArchDetails().getOpCount(); i++) {
                            CapstoneX86Details.X86Operand operand = x86Details.getArchDetails().getOperands()[i];
                            System.out.println("\tType: " + operand.getType());
                            System.out.println("\tReg: " + operand.getReg());
                            System.out.println("\tImm: " + operand.getImm());
                            if (operand.getMem() != null) {
                                System.out.println("\tMem:");
                                CapstoneX86Details.X86OpMem mem = operand.getMem();
                                System.out.println("\t\tSegment: " + mem.getSegment());
                                System.out.println("\t\tBase: " + mem.getBase());
                                System.out.println("\t\tIndex: " + mem.getIndex());
                                System.out.println("\t\tScale: " + mem.getScale());
                                System.out.println("\t\tDisp: " + mem.getDisp());
                            }
                        }
                    }

                    offset += instruction.getSize();
                    runtimeAddress += instruction.getSize();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## Development

The project uses the following configurations:
- Java preview features enabled
- Native access enabled for all unnamed modules
- Maven Central repository for dependencies
- Foreign Function & Memory API for native interop
- Memory management through Java's Foreign Memory API

## TODO

- [ ] Add support for more architectures
  - [X] X86
  - [X] ARM
  - [X] AArch64
  - [ ] SystemZ
  - [ ] M68K
  - [ ] MIPS
  - [ ] PPC
  - [ ] Sparc
  - [ ] XCore
  - [ ] TMS320C64x
  - [ ] M680X
  - [ ] evm
  - [ ] MOS65XX
  - [ ] WASM
  - [ ] BPF/eBPF
  - [ ] RiscV
  - [ ] SH
  - [ ] TriCore
  - [ ] Alpha
  - [ ] HPPA
  - [ ] LoongArch
  - [ ] Xtensa
  - [ ] ARC
- [ ] Java 8 Support via JNA
- [ ] Improve error handling and reporting
- [ ] Add more comprehensive documentation
- [ ] Create a test suite for all supported architectures
- [ ] Add performance benchmarks
- [ ] Set up GitHub Actions for multi-platform builds:
  - [ ] Windows
  - [ ] Linux
  - [ ] macOS

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the BSD 3-Clause License - see the LICENSE file for details. This is the same license as the original Capstone project.

The BSD 3-Clause License is a permissive open source license that allows you to:
- Use the code commercially
- Modify the code
- Distribute the code
- Use it privately
- Sublicense the code

The only requirements are:
- Include the original copyright notice
- Include the license text
- Include the list of conditions
- Include the following disclaimer: "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED." 
# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build

# Include any dependencies generated for this target.
include CMakeFiles/kcrypto.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/kcrypto.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/kcrypto.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kcrypto.dir/flags.make

CMakeFiles/kcrypto.dir/aes.c.o: CMakeFiles/kcrypto.dir/flags.make
CMakeFiles/kcrypto.dir/aes.c.o: ../aes.c
CMakeFiles/kcrypto.dir/aes.c.o: CMakeFiles/kcrypto.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/kcrypto.dir/aes.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kcrypto.dir/aes.c.o -MF CMakeFiles/kcrypto.dir/aes.c.o.d -o CMakeFiles/kcrypto.dir/aes.c.o -c /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/aes.c

CMakeFiles/kcrypto.dir/aes.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kcrypto.dir/aes.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/aes.c > CMakeFiles/kcrypto.dir/aes.c.i

CMakeFiles/kcrypto.dir/aes.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kcrypto.dir/aes.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/aes.c -o CMakeFiles/kcrypto.dir/aes.c.s

CMakeFiles/kcrypto.dir/md.c.o: CMakeFiles/kcrypto.dir/flags.make
CMakeFiles/kcrypto.dir/md.c.o: ../md.c
CMakeFiles/kcrypto.dir/md.c.o: CMakeFiles/kcrypto.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/kcrypto.dir/md.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kcrypto.dir/md.c.o -MF CMakeFiles/kcrypto.dir/md.c.o.d -o CMakeFiles/kcrypto.dir/md.c.o -c /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/md.c

CMakeFiles/kcrypto.dir/md.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kcrypto.dir/md.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/md.c > CMakeFiles/kcrypto.dir/md.c.i

CMakeFiles/kcrypto.dir/md.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kcrypto.dir/md.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/md.c -o CMakeFiles/kcrypto.dir/md.c.s

CMakeFiles/kcrypto.dir/stream.c.o: CMakeFiles/kcrypto.dir/flags.make
CMakeFiles/kcrypto.dir/stream.c.o: ../stream.c
CMakeFiles/kcrypto.dir/stream.c.o: CMakeFiles/kcrypto.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/kcrypto.dir/stream.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kcrypto.dir/stream.c.o -MF CMakeFiles/kcrypto.dir/stream.c.o.d -o CMakeFiles/kcrypto.dir/stream.c.o -c /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/stream.c

CMakeFiles/kcrypto.dir/stream.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kcrypto.dir/stream.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/stream.c > CMakeFiles/kcrypto.dir/stream.c.i

CMakeFiles/kcrypto.dir/stream.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kcrypto.dir/stream.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/stream.c -o CMakeFiles/kcrypto.dir/stream.c.s

CMakeFiles/kcrypto.dir/crypto_base.c.o: CMakeFiles/kcrypto.dir/flags.make
CMakeFiles/kcrypto.dir/crypto_base.c.o: ../crypto_base.c
CMakeFiles/kcrypto.dir/crypto_base.c.o: CMakeFiles/kcrypto.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/kcrypto.dir/crypto_base.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kcrypto.dir/crypto_base.c.o -MF CMakeFiles/kcrypto.dir/crypto_base.c.o.d -o CMakeFiles/kcrypto.dir/crypto_base.c.o -c /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/crypto_base.c

CMakeFiles/kcrypto.dir/crypto_base.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kcrypto.dir/crypto_base.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/crypto_base.c > CMakeFiles/kcrypto.dir/crypto_base.c.i

CMakeFiles/kcrypto.dir/crypto_base.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kcrypto.dir/crypto_base.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/crypto_base.c -o CMakeFiles/kcrypto.dir/crypto_base.c.s

# Object files for target kcrypto
kcrypto_OBJECTS = \
"CMakeFiles/kcrypto.dir/aes.c.o" \
"CMakeFiles/kcrypto.dir/md.c.o" \
"CMakeFiles/kcrypto.dir/stream.c.o" \
"CMakeFiles/kcrypto.dir/crypto_base.c.o"

# External object files for target kcrypto
kcrypto_EXTERNAL_OBJECTS =

libkcrypto.so: CMakeFiles/kcrypto.dir/aes.c.o
libkcrypto.so: CMakeFiles/kcrypto.dir/md.c.o
libkcrypto.so: CMakeFiles/kcrypto.dir/stream.c.o
libkcrypto.so: CMakeFiles/kcrypto.dir/crypto_base.c.o
libkcrypto.so: CMakeFiles/kcrypto.dir/build.make
libkcrypto.so: CMakeFiles/kcrypto.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C shared library libkcrypto.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/kcrypto.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kcrypto.dir/build: libkcrypto.so
.PHONY : CMakeFiles/kcrypto.dir/build

CMakeFiles/kcrypto.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/kcrypto.dir/cmake_clean.cmake
.PHONY : CMakeFiles/kcrypto.dir/clean

CMakeFiles/kcrypto.dir/depend:
	cd /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build /root/iwander/pi-dotnet/LinkerDesign.Crypto/Native/build/CMakeFiles/kcrypto.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/kcrypto.dir/depend


# TODO: ReleaseSafe does not function - this boi being low-key naughty

all: patch
	zig build -Doptimize=ReleaseSmall

debug: patch
	zig build -Doptimize=Debug

patch:
	@./patch_zigwin32.sh

clean:
	rm -rf zig-out zig-cache

.phony: clean

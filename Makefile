# TODO: ReleaseSafe does not function - this boi being low-key naughty

all:
	zig build -Doptimize=ReleaseSmall --release=small

debug:
	zig build -Doptimize=Debug

clean:
	rm -rf zig-out zig-cache

.phony: clean

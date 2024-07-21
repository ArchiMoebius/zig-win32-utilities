# TODO: ReleaseSafe does not function - this boi being low-key naughty

all:
	zig build -Doptimize=ReleaseSmall --release=small

debug:
	zig build -freference-trace -Doptimize=Debug

clean:
	rm -rf zig-out zig-cache .zig-cache

.phony: clean

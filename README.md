# fts_autosln

`fts_autosln` is a command line tool written in Rust that generates Visual Studio solutions from an application's `pdbs`.

It can process an `sln` from either both an `exe` on disk or a running process.

# Why

Why does this exist? It's a niche tool. The primary use cases are:

1. A project involves mixed build systems. For example native plugins + Unreal or Unity.
2. A project uses a build system that doesn't generate clean `.sln` files.

The intent is for the generated project to be used for code editing and debugging. It does not replace any existing build system.

# Usage

```
// from-file: recursively find and read pdbs from disk
fts_autosln.exe --sln-path foo.sln -source_roots "C:/path/to/src" from-file "C:/path/to/bin/foo.exe"

// from-process-name: load symbols via SymInitialize
fts_autosln.exe --sln-path foo.sln -source_roots "C:/path/to/src" from-process-name foo.exe
```

# Installation

Download from [Releases](https://github.com/forrestthewoods/fts_autosln/releases) or clone repository and build locally with Rust via `cargo build`.

# Additional Information

For more details please refer to the [blog post](fts_autosln: Build Visual Studio Solutions from PDBs).
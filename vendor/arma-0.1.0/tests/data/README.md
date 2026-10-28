# Initramfs fixtures

`initramfs.cpio` is a complete GNU cpio newc archive containing an executable
`init` with these bytes (including the final newline):

```sh
#!/bin/sh
printf 'arma initramfs fixture\n'
exec /bin/sh
```

It is an archive-format fixture, not a self-contained bootable userspace (there
is no `/bin/sh`). The image tests verify ingestion and PMI bytes, not execution.

Generated with GNU cpio, gzip and zstd, not required at test runtime:

```sh
# In a directory containing only the executable init shown above:
printf 'init\n' | cpio --create --format=newc --reproducible > initramfs.cpio
gzip -n -c initramfs.cpio > initramfs.cpio.gz
zstd -q -f initramfs.cpio -o initramfs.cpio.zst
```

cpio metadata includes the source file's mtime, so regeneration need not produce
identical bytes. Both compressed fixtures decode to the committed archive.

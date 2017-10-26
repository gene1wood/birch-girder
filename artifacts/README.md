The `artifacts` directory contains

# `birch-girder.zip`

This is the Python environment needed to upload to Lambda.
This is what's produced from the ec2 instructions in `docs/build-and-upload-birch-girder.md`.
It does not contain the birch-girder code itself or your `config.yaml`. The
commands to add each of those are in `docs/build-and-upload-birch-girder.md`

You can also generate this zip file (with possibly newer python modules)
on an Amazon Linux ec2 instance with the instructions in `docs/build-and-upload-birch-girder.md`
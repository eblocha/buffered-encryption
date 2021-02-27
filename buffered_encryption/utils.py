import io


def iter_chunks(file: io.BytesIO, chunk_size: int = 64 * 1024):
    """Read chunks from a file"""
    while True:
        data = file.read(chunk_size)
        if not data:
            break
        yield data

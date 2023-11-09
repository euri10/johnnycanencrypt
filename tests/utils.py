def _get_cert_data(filepath):
    "Returns the filepath content as bytes"
    with open(filepath, "rb", encoding="utf-8") as fobj:
        return fobj.read()


def verify_files(inputfile, decrypted_output):
    # read both the files
    with open(inputfile, encoding="utf-8") as f:
        original_text = f.read()

    with open(decrypted_output, encoding="utf-8") as f:
        decrypted_text = f.read()
    assert original_text == decrypted_text

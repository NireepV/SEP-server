import tkinter as tk

main = tk.Tk()
main.geometry('500x600')

scrollbar = tk.Scrollbar(main, orient='vertical')
scrollbar.pack(side='right', fill='y')

### Canvases ###
msg_frame = tk.Frame(main, yscrollcommand=scrollbar.set)
etry_frame = tk.Frame(main)

### Widgets ###
msg_etry = tk.Entry(etry_frame)
msg_etry.insert(0, "Type message here")

# Function to add messages
def send():
    if msg_etry.get() != "":
        # Create the message label
        label = tk.Label(msg_frame, text=msg_etry.get(), bg='blue')
        msg_etry.delete(0, tk.END)
        label.pack(side='top', anchor='e', padx='5', pady='3')

# Send button
sndbtn = tk.Button(etry_frame, text="Send", command=send)

scrollbar.config(command=msg_frame.yview)

### Layouts ###
etry_frame.pack(side='bottom', fill='x')
msg_frame.pack(expand=True, fill='both')

# Widget Layout #
sndbtn.pack(side='right', ipady=4)
msg_etry.pack(side='right', expand=True, fill='both', ipady=5)

main.mainloop()
import tkinter as tk

main = tk.Tk()
main.geometry('700x600')

### Canvases ###
msg_canvas = tk.Canvas(main)
etry_canvas = tk.Canvas(main)

### Widgets ###
msg_etry = tk.Entry(etry_canvas)
msg_etry.insert(0, "Type message here")

# Function to add messages
def send():
    if msg_etry.get() != '':
        # Create the message label
        label = tk.Label(msg_canvas, text=msg_etry.get(), background='blue')
        msg_etry.delete(0, tk.END)
        label.pack(side='top', anchor='e', padx='5', pady='3')

# Send button
sndbtn = tk.Button(etry_canvas, text="Send", command=send)

### Scroll Bar ###
scrollbar = tk.Scrollbar(msg_canvas, orient='vertical', command=msg_canvas.yview)
msg_canvas.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side='right', fill='y')
msg_canvas.bind('<MouseWheel>', lambda event: msg_canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units'))

### Layouts ###
etry_canvas.pack(side='bottom', fill='x')
msg_canvas.pack(expand=True, fill='both')

# Widget Layout #
sndbtn.pack(side='right', ipady=4)
msg_etry.pack(side='right', expand=True, fill='both', ipady=5)

main.mainloop()
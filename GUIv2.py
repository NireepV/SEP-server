import tkinter as tk

main = tk.Tk()
main.geometry('500x600')

# Scrollbar
scrollbar = tk.Scrollbar(main, orient='vertical')
scrollbar.pack(side='right', fill='y')

# Text widget to hold messages
msg_text = tk.Text(main, yscrollcommand=scrollbar.set, wrap="word", state="disabled", spacing1=7)
msg_text.pack(expand=True, fill='both')

# Entry frame for input
etry_frame = tk.Frame(main)

# Entry widget
msg_etry = tk.Entry(etry_frame)
msg_etry.insert(0, "Type message here")

# Function to add messages
def send():
    if msg_etry.get() != "":
        msg_text.config(state="normal")  # Enable writing in Text widget
        msg_text.insert(tk.END, "YOU: " + msg_etry.get() + "\n")  # Insert message
        msg_etry.delete(0, tk.END)  # Clear entry box
        msg_text.config(state="disabled")  # Disable Text widget again
        msg_text.see(tk.END)  # Auto-scroll to the bottom

# Send button
sndbtn = tk.Button(etry_frame, text="Send", command=send)

# Scrollbar config
scrollbar.config(command=msg_text.yview)

# Layout for entry and send button
etry_frame.pack(side='bottom', fill='x')
sndbtn.pack(side='right', ipady=4)
msg_etry.pack(side='right', expand=True, fill='both', ipady=5)

main.mainloop()

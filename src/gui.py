import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from aes import encrypt, decrypt
import os

class ModernEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-CBC Encryption/Decryption")
        self.setup_styles()
        self.status_var = tk.StringVar()
        
        self.root.geometry("600x850")
        self.root.resizable(False, False)
        
        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        tabs_config = [
            ("encrypt", "Encrypt", self.encrypt_text),
            ("decrypt", "Decrypt", self.decrypt_text),
        ]
        
        for prefix, title, command in tabs_config:
            tab = ttk.Frame(self.notebook, style="Card.TFrame")
            self.notebook.add(tab, text=title)
            self.setup_crypto_tab(tab, prefix, title, command)
        
        self.file_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        self.notebook.add(self.file_tab, text="Files")
        self.setup_file_tab()
        
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

    def setup_crypto_tab(self, tab, prefix, title, command):
        container = ttk.Frame(tab, style="Card.TFrame", padding="20")
        container.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(container, text=f"Text {title}", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 20)
        )
        
        key_frame = self.create_key_frame(container, f"{prefix}_key", f"{title} Key")
        key_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        if prefix == "encrypt":
            iv_frame = self.create_iv_frame(container, f"{prefix}_iv")
            iv_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        
        input_frame = self.create_text_frame(
            container,
            "Plain Text" if prefix == "encrypt" else "Encrypted Text",
            f"{prefix}_input",
            'Segoe UI' if prefix == "encrypt" else 'Consolas'
        )
        input_frame.grid(row=3 if prefix == "encrypt" else 2, column=0, sticky="ew", pady=(0, 20))
        
        ttk.Button(
            container,
            text=title,
            style="Action.TButton",
            command=command
        ).grid(row=4 if prefix == "encrypt" else 3, column=0, pady=(0, 20))
        
        output_frame = self.create_text_frame(
            container,
            f"{title}ed Text",
            f"{prefix}_output",
            'Consolas' if prefix == "encrypt" else 'Segoe UI',
            readonly=True
        )
        output_frame.grid(row=5 if prefix == "encrypt" else 4, column=0, sticky="ew")

    def create_key_frame(self, parent, prefix, title):
        frame = ttk.LabelFrame(parent, text=title, style="Card.TLabelframe", padding="10")
        
        var = tk.StringVar()
        setattr(self, f"{prefix}_var", var)
        var.trace_add("write", lambda *args: self.update_char_count(prefix))
        
        label_frame = ttk.Frame(frame, style="Card.TFrame")
        label_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Label(label_frame, text="Enter a 16-character key:", style="Label.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        
        count_label = ttk.Label(label_frame, text="0/16 characters", style="Counter.TLabel")
        count_label.grid(row=0, column=1, sticky="e", padx=(10, 0))
        setattr(self, f"{prefix}_count_label", count_label)
        
        label_frame.grid_columnconfigure(1, weight=1)
        
        entry = ttk.Entry(frame, textvariable=var, style="Entry.TEntry", width=50)
        entry.grid(row=1, column=0, sticky="ew")
        setattr(self, f"{prefix}_entry", entry)
        
        return frame

    def create_iv_frame(self, parent, prefix):
        frame = ttk.LabelFrame(parent, text="Initialization Vector (IV)", style="Card.TLabelframe", padding="10")
        
        var = tk.StringVar()
        setattr(self, f"{prefix}_var", var)
        
        label_frame = ttk.Frame(frame, style="Card.TFrame")
        label_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Label(label_frame, text="Enter a 16-byte IV (optional, hexadecimal):", style="Label.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        
        entry = ttk.Entry(frame, textvariable=var, style="Entry.TEntry", width=50)
        entry.grid(row=1, column=0, sticky="ew")
        setattr(self, f"{prefix}_entry", entry)
        
        ttk.Button(
            frame,
            text="Generate Random IV",
            style="Action.TButton",
            command=lambda: var.set(os.urandom(16).hex())
        ).grid(row=2, column=0, pady=(10, 0))
        
        return frame

    def create_text_frame(self, parent, title, prefix, font_family, readonly=False):
        frame = ttk.LabelFrame(parent, text=title, style="Card.TLabelframe", padding="10")
        
        ttk.Label(frame, text="Result:" if readonly else f"Enter text to {title.lower()}:", 
                 style="Label.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        text_widget = tk.Text(
            frame,
            height=6,
            width=50,
            font=(font_family, 10),
            wrap=tk.WORD,
            relief="solid",
            borderwidth=1,
            bg='#f8f9fa' if readonly else 'white'
        )
        text_widget.grid(row=1, column=0, sticky="ew")
        
        if readonly:
            text_widget.config(state='disabled')
            ttk.Button(
                frame,
                text="Copy to Clipboard",
                style="Action.TButton",
                command=lambda: self.copy_to_clipboard(text_widget)
            ).grid(row=2, column=0, pady=(10, 0))
        
        setattr(self, f"{prefix}_text", text_widget)
        return frame

    def setup_file_tab(self):
        container = ttk.Frame(self.file_tab, style="Card.TFrame", padding="20")
        container.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(container, text="File Encryption/Decryption", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 20)
        )
        
        key_frame = self.create_key_frame(container, "file_key", "Encryption/Decryption Key")
        key_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        iv_frame = self.create_iv_frame(container, "file_iv")
        iv_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        
        file_frame = ttk.LabelFrame(container, text="File Selection", style="Card.TLabelframe", padding="10")
        file_frame.grid(row=3, column=0, sticky="ew", pady=(0, 20))
        
        self.file_path_var = tk.StringVar()
        ttk.Label(file_frame, text="Selected file:", style="Label.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 5)
        )
        
        self.file_path_entry = ttk.Entry(
            file_frame,
            textvariable=self.file_path_var,
            state='readonly',
            style="Entry.TEntry",
            width=40
        )
        self.file_path_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        
        ttk.Button(file_frame, text="Browse", style="Action.TButton", command=self.browse_file).grid(
            row=1, column=1
        )
        
        file_frame.grid_columnconfigure(0, weight=1)
        
        button_frame = ttk.Frame(container, style="Card.TFrame")
        button_frame.grid(row=4, column=0, pady=(0, 20))
        
        ttk.Button(button_frame, text="Encrypt File", style="Action.TButton", command=self.encrypt_file).grid(
            row=0, column=0, padx=5
        )
        
        ttk.Button(button_frame, text="Decrypt File", style="Action.TButton", command=self.decrypt_file).grid(
            row=0, column=1, padx=5
        )

    def setup_styles(self):
        style = ttk.Style()
        styles = {
            "Card.TFrame": {"background": "white"},
            "Card.TLabelframe": {"background": "white"},
            "Card.TLabelframe.Label": {
                "font": ('Segoe UI', 10, 'bold'),
                "foreground": "#2c3e50",
                "background": "white"
            },
            "Title.TLabel": {
                "font": ('Segoe UI', 16, 'bold'),
                "foreground": "#2c3e50",
                "background": "white"
            },
            "Label.TLabel": {
                "font": ('Segoe UI', 10),
                "foreground": "#2c3e50",
                "background": "white"
            },
            "Counter.TLabel": {
                "font": ('Segoe UI', 10),
                "foreground": "#666666",
                "background": "white"
            },
            "Action.TButton": {
                "font": ('Segoe UI', 10, 'bold'),
                "padding": 10
            }
        }
        
        for name, config in styles.items():
            style.configure(name, **config)
        
        self.root.configure(bg='#f0f2f5')

    def update_char_count(self, prefix):
        var = getattr(self, f"{prefix}_var")
        label = getattr(self, f"{prefix}_count_label")
        count = len(var.get())
        label.config(
            text=f"{count}/16 characters",
            foreground="#2c3e50" if count == 16 else "#dc3545" if count > 16 else "#666666"
        )

    def encrypt_text(self):
        key = self.encrypt_key_var.get()
        text = self.encrypt_input_text.get("1.0", tk.END).strip()
        iv = self.encrypt_iv_var.get()
        
        try:
            if len(key) != 16:
                raise ValueError("Key must be exactly 16 characters long!")
            
            # Convert IV from hex if provided
            if iv:
                try:
                    if len(iv) != 32:  # 16 bytes in hex = 32 characters
                        raise ValueError("IV must be exactly 32 hex characters long!")
                    iv_bytes = bytes.fromhex(iv)
                except ValueError:
                    raise ValueError("Invalid IV format! Please use hexadecimal format or generate a random IV.")
            else:
                iv_bytes = None
            
            encrypted = encrypt(key, text, iv_bytes)
            
            self.encrypt_output_text.config(state='normal')
            self.encrypt_output_text.delete("1.0", tk.END)
            self.encrypt_output_text.insert("1.0", encrypted)
            self.encrypt_output_text.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        key = self.decrypt_key_var.get()
        text = self.decrypt_input_text.get("1.0", tk.END).strip()
        
        try:
            if len(key) != 16:
                raise ValueError("Key must be exactly 16 characters long!")
            
            try:
                # Check if the input is a valid hex string
                int(text, 16)
                if len(text) < 64:  # 32 chars for IV + at least 32 chars for one block
                    raise ValueError("Invalid encrypted text: Too short")
            except ValueError as e:
                if "invalid literal for int() with base 16" in str(e):
                    raise ValueError("Invalid encrypted text: Please enter a valid encrypted message (hexadecimal format)")
                raise e
            
            decrypted = decrypt(key, text)
            
            self.decrypt_output_text.config(state='normal')
            self.decrypt_output_text.delete("1.0", tk.END)
            self.decrypt_output_text.insert("1.0", decrypted.decode('utf-8', errors='replace'))
            self.decrypt_output_text.config(state='disabled')
            
        except UnicodeDecodeError:
            messagebox.showerror("Error", "Unable to decode the decrypted text. The key might be incorrect.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def copy_to_clipboard(self, text_widget):
        self.root.clipboard_clear()
        text = text_widget.get("1.0", tk.END).strip()
        self.root.clipboard_append(text)
        messagebox.showinfo("Success", "Text copied to clipboard!")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path_var.set(filename)

    def encrypt_file(self):
        key = self.file_key_var.get()
        iv = self.file_iv_var.get()
        input_path = self.file_path_var.get()
        
        if not input_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        try:
            if len(key) != 16:
                raise ValueError("Key must be exactly 16 characters long!")
            
            # Convert IV from hex if provided
            if iv:
                try:
                    if len(iv) != 32:  # 16 bytes in hex = 32 characters
                        raise ValueError("IV must be exactly 32 hex characters long!")
                    iv_bytes = bytes.fromhex(iv)
                except ValueError:
                    raise ValueError("Invalid IV format! Please use hexadecimal format or generate a random IV.")
            else:
                iv_bytes = None
            
            output_path = input_path + '.encrypted'
            
            with open(input_path, 'rb') as f:
                data = f.read()
            
            encrypted = encrypt(key, data, iv_bytes)
            encrypted_data = bytes.fromhex(encrypted)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.status_var.set(f"File encrypted successfully! Saved as: {output_path}")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Encryption failed!")

    def decrypt_file(self):
        key = self.file_key_var.get()
        input_path = self.file_path_var.get()
        
        if not input_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        try:
            if len(key) != 16:
                raise ValueError("Key must be exactly 16 characters long!")
            
            if input_path.endswith('.encrypted'):
                output_path = input_path[:-10]
                base, ext = os.path.splitext(output_path)
                output_path = f"{base}_decrypted{ext}"
            else:
                base, ext = os.path.splitext(input_path)
                output_path = f"{base}_decrypted{ext}"
            
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted = decrypt(key, encrypted_data.hex())
            
            with open(output_path, 'wb') as f:
                if isinstance(decrypted, str):
                    f.write(decrypted.encode('latin1'))
                else:
                    f.write(decrypted)
            
            self.status_var.set(f"File decrypted successfully! Saved as: {output_path}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_path}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Decryption failed!")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernEncryptionGUI(root)
    root.mainloop()
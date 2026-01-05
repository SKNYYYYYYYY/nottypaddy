import tkinter as tk
from tkinter import ttk
import urllib.request
import json
import webbrowser
import ssl

# ---------- Config ----------
CURRENT_VERSION = "2.0"
UPDATE_URL = "https://clippadd.vercel.app/update.json"

# ---------- Main Window ----------
root = tk.Tk()
root.title("ClipPad")
root.geometry("520x720")

# ---------- Variables ----------
enable_var = tk.BooleanVar(value=True)
startkey_var = tk.BooleanVar(value=False)
swap_var = tk.StringVar(value="Pass")
startkey_status_var = tk.StringVar(value="Pass")

entries = []
field_data = []

# ---------- Undo State ----------
undo_state = {}

# ---------- Functions ----------
def paste_from_clipboard(entry):
    try:
        text = root.clipboard_get()
        entry.delete(0, tk.END)
        entry.insert(0, text)
    except tk.TclError:
        pass

def toggle_fields():
    state = "normal" if enable_var.get() else "disabled"
    for e in entries:
        e.config(state=state)
    free_text.config(state=state)

def toggle_extra():
    if extra_frame.winfo_ismapped():
        extra_frame.pack_forget()
        more_button.config(text="More")
    else:
        extra_frame.pack(fill="x", pady=5)
        more_button.config(text="Less")

def toggle_serial_visibility(*args):
    if startkey_var.get():
        serial_row.pack_forget()
    else:
        serial_row.pack(fill="x", pady=4)

def show_call_alert():
    call_label.config(foreground="red")
    call_entry.config(bg="#ffcccc")
    call_alert.pack(side="left", padx=8)

def hide_call_alert(*args):
    call_label.config(foreground="black")
    call_entry.config(bg="white")
    call_alert.pack_forget()

def copy_all():
    if not call_var.get().strip():
        show_call_alert()
        return
    else:
        hide_call_alert()

    lines = []
    lines.append(f"Calling No: {call_var.get().strip()}")

    if not startkey_var.get():
        if swap_var.get() == "Pass":
            lines.append(
                "Sim swap done successfully and adv on mpesa activation\nSub vetted on:"
            )
        else:
            lines.append(
                "swap not done failed vetting\nTo confirm details/visit RC\nSub vetted on:"
            )

    if startkey_var.get():
        if startkey_status_var.get() == "Pass":
            lines.append("Sub given startkey educated on DIY procedure and sms sent.")
        else:
            lines.append(
                "Start key not given.\nTo confirm details or visit RC\nSub vetted on:"
            )

    for label, entry in field_data:
        if label == "Serial no" and startkey_var.get():
            continue
        val = entry.get().strip()
        if val:
            lines.append(f"{label}: {val}")

    notes = free_text.get("1.0", tk.END).strip()
    if notes:
        lines.append("\nNotes:\n" + notes)

    root.clipboard_clear()
    root.clipboard_append("\n".join(lines))

def copy_serial():
    if startkey_var.get():
        return
    root.clipboard_clear()
    root.clipboard_append(serial_var.get())

def copy_calling():
    root.clipboard_clear()
    root.clipboard_append(call_var.get())

def reversal_copy():
    root.clipboard_clear()
    root.clipboard_append(
        "Reversal initiated and sub adv on hakikisha and sla 72 working hrs"
    )

def rc_copy():
    root.clipboard_clear()
    root.clipboard_append("sub adv to visit rc")

def sla_copy():
    root.clipboard_clear()
    root.clipboard_append("reversal within sla sub adv to be patient")

def update_digit_count(*args):
    digit_count_label.config(text=f"Digits: {len(serial_var.get())}")

# ---------- Undo Logic ----------
def save_undo_state():
    undo_state.clear()
    undo_state["call"] = call_var.get()
    undo_state["serial"] = serial_var.get()
    undo_state["notes"] = free_text.get("1.0", tk.END)
    undo_state["fields"] = [entry.get() for _, entry in field_data]

def undo_clear():
    if not undo_state:
        return

    call_var.set(undo_state["call"])
    serial_var.set(undo_state["serial"])

    free_text.delete("1.0", tk.END)
    free_text.insert("1.0", undo_state["notes"])

    for (label, entry), value in zip(field_data, undo_state["fields"]):
        entry.delete(0, tk.END)
        entry.insert(0, value)

def clear_all():
    save_undo_state()

    for _, entry in field_data:
        entry.delete(0, tk.END)

    call_var.set("")
    serial_var.set("89254021")
    free_text.delete("1.0", tk.END)
    hide_call_alert()

# ---------- Update Logic ----------
def check_for_updates():
    try:
        context = ssl._create_unverified_context()  # skip SSL verification
        with urllib.request.urlopen(UPDATE_URL, timeout=5, context=context) as response:
            data = json.loads(response.read().decode())
        latest_version = data.get("latest_version")
        download_url = data.get("download_url")
        notes = data.get("notes", "")

        if latest_version != CURRENT_VERSION:
            return {
                "update_available": True,
                "latest_version": latest_version,
                "download_url": download_url,
                "notes": notes
            }
        else:
            return {"update_available": False, "latest_version": latest_version}
    except Exception as e:
        return {"update_available": False, "error": str(e)}


def show_update_page():
    for widget in root.winfo_children():
        widget.destroy()

    ttk.Button(root, text="← Back", command=build_main_ui).pack(
        anchor="w", padx=10, pady=5
    )

    container = ttk.Frame(root, padding=20)
    container.pack(fill="both", expand=True)

    ttk.Label(
        container, text="Checking for updates…", font=("Segoe UI", 10, "bold")
    ).pack(anchor="w", pady=(0, 10))

    status_lbl = ttk.Label(container, text="")
    status_lbl.pack(anchor="w", pady=(0, 15))

    def update_ui():
        result = check_for_updates()
        if result.get("update_available"):
            status_lbl.config(
                text=f"Update available: v{result['latest_version']}\nCurrent: {CURRENT_VERSION}",
                foreground="green",
            )
            ttk.Label(
                container, text=result.get("notes", ""), foreground="gray"
            ).pack(anchor="w", pady=(0, 5))

            link = ttk.Label(
                container, text="Download update", foreground="blue", cursor="hand2"
            )
            link.pack(anchor="w")
            link.bind(
                "<Button-1>", lambda e: webbrowser.open(result["download_url"])
            )
        else:
            msg = "You are running the latest version."
            if result.get("error"):
                msg += f"\n(Update check failed: {result['error']})"
            status_lbl.config(text=msg, foreground="gray")

    root.after(100, update_ui)

# ---------- Main UI ----------
def build_main_ui():
    for widget in root.winfo_children():
        widget.destroy()

    global call_var, call_entry, call_label, call_alert
    global serial_var, serial_row, digit_count_label
    global free_text, extra_frame, more_button

    entries.clear()
    field_data.clear()

    # Title
    title_frame = ttk.Frame(root)
    title_frame.pack(fill="x", pady=5, padx=10)

    ttk.Label(title_frame, text="", font=("Segoe UI", 10, "bold")).pack(
        side="left"
    )

    ttk.Button(title_frame, text="ℹ", width=2, command=show_update_page).pack(
        side="left", padx=(4, 0)
    )

    top_frame = ttk.Frame(root)
    top_frame.pack(pady=5, fill="x")

    # Calling No
    call_var = tk.StringVar()
    call_row = ttk.Frame(top_frame)
    call_row.pack(fill="x", pady=4)

    call_label = ttk.Label(call_row, text="Calling No:", width=12)
    call_label.pack(side="left")

    call_entry = tk.Entry(call_row, textvariable=call_var)
    call_entry.pack(side="left", expand=True, fill="x", padx=5)

    ttk.Button(call_row, text="Paste",
               command=lambda: paste_from_clipboard(call_entry)).pack(side="right")
    ttk.Button(call_row, text="Copy", command=copy_calling).pack(
        side="right", padx=5
    )

    call_var.trace_add("write", hide_call_alert)

    # Swap / Startkey
    ttk.Label(top_frame, text="Swap Status:").pack(side="left", padx=5)
    ttk.Combobox(
        top_frame, textvariable=swap_var, values=["Pass", "Fail"],
        state="readonly", width=10
    ).pack(side="left", padx=5)

    startkey_var.trace_add("write", toggle_serial_visibility)
    ttk.Checkbutton(top_frame, text="Startkey", variable=startkey_var).pack(
        side="left", padx=5
    )
    ttk.Combobox(
        top_frame, textvariable=startkey_status_var,
        values=["Pass", "Fail"], state="readonly", width=10
    ).pack(side="left", padx=5)

    ttk.Checkbutton(root, text="Enable inputs",
                    variable=enable_var, command=toggle_fields).pack(pady=5)

    frame = ttk.Frame(root)
    frame.pack(padx=10, fill="x")

    def create_row(label, parent=frame):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=12).pack(side="left")
        entry = ttk.Entry(row)
        entry.pack(side="left", expand=True, fill="x", padx=5)
        ttk.Button(row, text="Paste",
                   command=lambda: paste_from_clipboard(entry)).pack(side="right")
        entries.append(entry)
        field_data.append((label, entry))
        return entry

    create_row("Name")
    create_row("YOB")
    create_row("ID")
    create_row("Airtime bal")
    create_row("Mpesa bal")

    serial_var = tk.StringVar(value="89254021")
    serial_row = ttk.Frame(frame)
    serial_row.pack(fill="x", pady=4)

    ttk.Label(serial_row, text="Serial no:", width=12).pack(side="left")
    serial_entry = ttk.Entry(serial_row, textvariable=serial_var)
    serial_entry.pack(side="left", expand=True, fill="x", padx=5)

    ttk.Button(serial_row, text="Paste",
               command=lambda: paste_from_clipboard(serial_entry)).pack(side="right")
    ttk.Button(serial_row, text="Copy",
               command=copy_serial).pack(side="right", padx=5)

    digit_count_label = ttk.Label(serial_row)
    digit_count_label.pack(side="right", padx=5)
    serial_var.trace_add("write", update_digit_count)

    entries.append(serial_entry)
    field_data.append(("Serial no", serial_entry))

    extra_frame = ttk.Frame(frame)
    extra_frame.pack_forget()
    create_row("M-Shwari Limit", extra_frame)
    create_row("Fuliza limit", extra_frame)
    create_row("2txns:", extra_frame)
    create_row("2fdns:", extra_frame)
    create_row("Reg", extra_frame)

    more_button = ttk.Button(root, text="More", command=toggle_extra)
    more_button.pack(pady=10)

    ttk.Label(root, text="Notes / Free Text:").pack(anchor="w", padx=10)
    free_text = tk.Text(root, height=6)
    free_text.pack(fill="x", padx=10, pady=5)

    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=10, pady=10)

    left_btns = ttk.Frame(bottom)
    left_btns.pack(side="left", padx=5)

    ttk.Button(left_btns, text="Reversal",
               command=reversal_copy).pack(fill="x", pady=2)
    ttk.Button(left_btns, text="rc",
               command=rc_copy).pack(fill="x", pady=2)
    ttk.Button(left_btns, text="sla",
               command=sla_copy).pack(fill="x", pady=2)

    ttk.Button(bottom, text="Copy All",
               command=copy_all).pack(side="left", padx=5)

    call_alert = ttk.Label(bottom, text="⚠ Missing Calling No",
                           foreground="#b00020")
    call_alert.pack_forget()

    ttk.Button(bottom, text="Undo",
               command=undo_clear).pack(side="right", padx=5)

    ttk.Button(bottom, text="Clear All",
               command=clear_all).pack(side="right")

    toggle_serial_visibility()

# ---------- Start ----------
build_main_ui()
root.mainloop()
